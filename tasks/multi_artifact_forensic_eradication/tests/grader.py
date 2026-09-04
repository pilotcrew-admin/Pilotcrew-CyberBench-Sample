#!/usr/bin/env python3
"""Semantic verifier for the defensive multi-artifact response outcome."""
from __future__ import annotations
import datetime as dt
import json
import os
import re
from pathlib import Path

STATE=Path(os.environ.get("IR_STATE","/case/live/state.json"))
REPORT=Path(os.environ.get("IR_REPORT","/app/incident_report.json"))
EVIDENCE=Path(os.environ.get("IR_EVIDENCE","/evidence"))
LOGDIR=Path(os.environ.get("LOG_DIR","/logs/verifier"))
MAL_SHA="27c1b956a376f025da54daeae5b3f9b9d12af076646712a31f4963ee3f743b73"
RELAY_SHA="74f740bc25ef325f87c3d1db53c6f8bee500f7d5270e15857df24ac7a5b86e82"
VENDOR_SHA="9a02b89bc7d921bb7899da21a523c8aa1064a3d9029ce46b5003190b4ceea11d"
VAULT_SHA="5a1ab623fda7df3cda48fc2d29a914c17ae700b3ceb79589d18bbd111b7f402d"
VAULT_APPROVED_SHA="976fa9317978a4fc326b42a008f323e0782222049004c5783eb4e9b805cfbc36"
ROGUE_FP="SHA256:Q7aP1Wz4kD9nY2cLm8oRf6vH3sJ5uX0eBqTtN4iKp6M"
ROGUE2_FP="SHA256:Zx4Kp9Vm2Qa7Nf6Rt1Yw8Hs3Lc5Db0GeUj4Mi7Po2As"
APPROVED_FP="SHA256:f0nRq8M0P4KxZ3TSxq1U7vWlYVzwQbQzdN0cP6q2Y9A"
APPROVED2_FP="SHA256:Vn5Rx1Tq8Ka3Lc7Ym2Wp9Hs4Df6Bj0ZuEe3Ni8Go1Cs"
HOSTS={"acct-ws-04","backup-gw-02","vault-prx-03"}
APPROVED_IPS={"192.0.2.44","203.0.113.88"}
BAD_IPS={"198.51.100.77","203.0.113.201","198.51.100.203"}
D={"reward":0.0,"subscores":{},"problems":[]}

def problem(area,msg): D["problems"].append(f"[{area}] {msg}")

def load_json(path,area):
    try:return json.loads(path.read_text())
    except (OSError,json.JSONDecodeError) as exc:
        problem(area,f"cannot read valid JSON from {path}: {exc}"); return None

def as_text(value):
    try:return json.dumps(value,sort_keys=True).casefold()
    except TypeError:return str(value).casefold()

GENERIC_LOCATORS={"parent","process","process_name","image","python3","powershell","powershell.exe","sshd","fingerprint","assets","description","windowstyle","execstart","registry_path","target_server","destination_port","record_id","time_utc","command_line","pid","host","source_ip","destination_ip"}

def nested_keys(value):
    out=set()
    if isinstance(value,dict):
        out.update(str(k).casefold() for k in value)
        for v in value.values():out.update(nested_keys(v))
    elif isinstance(value,list):
        for v in value:out.update(nested_keys(v))
    return out

def generic_locator(loc,path,raw):
    low=loc.strip().casefold()
    if low in GENERIC_LOCATORS:return True
    keys=set()
    try:
        if path.suffix==".json":keys=nested_keys(json.loads(raw))
        elif path.suffix==".jsonl":
            for line in raw.splitlines():
                if line.strip():keys.update(nested_keys(json.loads(line)))
        elif path.suffix==".csv":keys={x.strip().casefold() for x in raw.splitlines()[0].split(",")}
    except (json.JSONDecodeError,IndexError):
        pass
    if low in keys:return True
    if path.suffix.casefold() in {".service",".timer",".ini",".conf"} and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*",loc.strip()):
        for line in raw.splitlines():
            if "=" in line and line.split("=",1)[0].strip().strip('"').casefold()==low:return True
    return False

def citation(c):
    """Resolve a non-generic locator to exactly one source record/line."""
    if not isinstance(c,dict) or set(c)!={"path","locator"} or not isinstance(c.get("path"),str) or not isinstance(c.get("locator"),str):
        return False,"citation must contain exactly string path and locator fields",None,None
    rel=Path(c["path"])
    if rel.is_absolute() or ".." in rel.parts:
        return False,"citation path must be relative and cannot contain '..'",None,None
    p=EVIDENCE/rel
    try:
        if not p.is_file():return False,f"cited artifact does not exist: {rel}",None,None
        raw=p.read_text(errors="replace");lines=raw.splitlines()
    except OSError as exc:return False,f"cannot read cited artifact {rel}: {exc}",None,None
    loc=c["locator"].strip()
    if len(loc)<6:return False,f"citation locator too short in {rel}",None,None
    if generic_locator(loc,p,raw):return False,f"citation locator is a generic field/program token in {rel}: {loc}",None,None
    matches=[line.strip() for line in lines if loc.casefold() in line.casefold()]
    if not matches:return False,f"locator not found in cited artifact {rel}: {loc}",None,None
    if len(matches)!=1:return False,f"locator is not unique to one source record in {rel}: {loc}",None,None
    return True,"",str(rel),matches[0]

def citations(obj,area,minimum=1):
    ev=obj.get("evidence") if isinstance(obj,dict) else None
    if not isinstance(ev,list) or len(ev)<minimum:
        problem(area,f"requires at least {minimum} evidence citation(s)");return set(),[],False
    paths=set();segments=[];valid=True
    for item in ev:
        ok,msg,path,segment=citation(item)
        if not ok:problem(area,msg);valid=False
        else:paths.add(path);segments.append(segment)
    return paths,segments,valid

def selected_evidence(report):
    """Resolve the report's valid citations as one semantic evidence graph.

    Findings keep controlled fields, while corroboration may be cited in any
    report section rather than duplicated mechanically into every object.
    """
    paths=set();segments=[]
    def walk(value):
        if isinstance(value,dict):
            if set(value)=={"path","locator"}:
                ok,_,path,segment=citation(value)
                if ok: paths.add(path);segments.append(segment)
            else:
                for child in value.values():walk(child)
        elif isinstance(value,list):
            for child in value:walk(child)
    walk(report)
    return paths,segments

def family(path):
    p=path.casefold()
    if p.startswith("alerts/"):return "alert"
    if "windows/security" in p:return "windows-security"
    if "windows/sysmon" in p:return "sysmon"
    if p.startswith("registry/"):return "registry"
    if p.startswith("linux/") and "auth" in p:return "linux-auth"
    if p.startswith("linux/") and "audit" in p:return "linux-audit"
    if "memory/" in p and "process" in p:return "memory-process"
    if "memory/" in p and "socket" in p:return "memory-socket"
    if p.startswith("network/"):return "network"
    if p.startswith("filesystem/"):return "filesystem"
    if p.startswith("cmdb/"):return "cmdb"
    return p.split('/',1)[0]

def evidence_text(segments):return "\n".join(segments).casefold()

def contains_all(text,*values):return all(str(v).casefold() in text for v in values)

def check_state(state):
    ok=True
    def need(cond,msg):
        nonlocal ok
        if not cond: ok=False; problem("state",msg)
    if not isinstance(state,dict):return False
    try:
        ah=state["hosts"]["acct-ws-04"]; bh=state["hosts"]["backup-gw-02"]
        vh=state["hosts"]["vault-prx-03"]; db=state["hosts"]["report-db-01"]
        need(not ah["startup_entries"]["HKCU-17"]["enabled"],"alerted registry startup still enabled")
        need(ah["artifacts"]["FILE-221"]["quarantined"],"alerted PowerShell payload not quarantined")
        need(not bh["startup_entries"]["UNIT-77"]["enabled"],"backup gateway systemd persistence still enabled")
        need(bh["artifacts"]["FILE-914"]["quarantined"],"backup gateway relay payload not quarantined")
        need(not bh["ssh_keys"]["KEY-88"]["present"],"unauthorized backup gateway key still present")
        need(not vh["startup_entries"]["UNIT-93"]["enabled"],"vault proxy systemd persistence still enabled")
        need(vh["artifacts"]["FILE-931"]["quarantined"],"vault proxy relay payload not quarantined")
        need(not vh["ssh_keys"]["KEY-94"]["present"],"unauthorized vault proxy key still present")
        need(bh["ssh_keys"]["KEY-73"]["present"],"managed backup-gateway SSH key was removed")
        need(vh["ssh_keys"]["KEY-91"]["present"],"managed vault-proxy SSH key was removed")
        need(ah["startup_entries"]["TASK-44"]["enabled"],"legitimate month-end task was disabled")
        need(not ah["artifacts"]["FILE-310"]["quarantined"],"legitimate ledger script was quarantined")
        need(bh["startup_entries"]["TIMER-12"]["enabled"],"approved inventory timer was disabled")
        need(not bh["artifacts"]["FILE-701"]["quarantined"],"approved inventory binary was quarantined")
        need(vh["startup_entries"]["UNIT-92"]["enabled"],"approved vault-health service was disabled")
        need(not vh["artifacts"]["FILE-930"]["quarantined"],"approved vault-health binary was quarantined")
        need(db["startup_entries"]["DB-11"]["enabled"] and not db["artifacts"]["DBFILE-1"]["quarantined"],"clean reporting host was altered")
        need(not state["sessions"]["S-4101"]["active"],"incident backupsvc session remains active")
        need(not state["sessions"]["S-4302"]["active"],"incident vaultsync session remains active")
        need(state["sessions"]["S-6200"]["active"],"legitimate reporting session was revoked")
        backup=state["credentials"]["CORP\\backupsvc"]; vault=state["credentials"]["CORP\\vaultsync"]
        reporting=state["credentials"]["CORP\\svc_reporting"]
        need(backup["rotated"] and backup["version"]>7,"exposed backupsvc credential was not rotated")
        need(vault["rotated"] and vault["version"]>2,"exposed vaultsync credential was not rotated")
        need(not reporting["rotated"] and reporting["version"]==4,"unexposed reporting credential was rotated")
        blocks=set(state["blocked_indicators"])
        need(BAD_IPS<=blocks,"trusted hostile network indicators are not all blocked")
        need(not (APPROVED_IPS & blocks),"an approved partner destination was blocked")
    except (KeyError,TypeError) as exc:
        problem("state",f"state structure is missing required range objects: {exc}"); return False
    return ok

def check_recovery(state):
    ok=True
    def need(cond,msg):
        nonlocal ok
        if not cond:ok=False;problem("recovery",msg)
    if not isinstance(state,dict):return False
    try:
        b=state["credentials"]["CORP\\backupsvc"]; v=state["credentials"]["CORP\\vaultsync"]
        nb=state["services"]["nightly-backup"]
        need(nb["status"]=="running","nightly-backup is not running")
        need(nb["host"]=="backup-gw-02" and nb["principal"]=="CORP\\backupsvc" and nb["credential_version"]==b["version"],"nightly-backup is not rebound to current backupsvc trust")
        at=state["services"]["archive-transfer"]
        need(at["status"]=="running","archive-transfer is not running")
        need(at["host"]=="vault-prx-03" and at["principal"]=="CORP\\vaultsync" and at["credential_version"]==v["version"],"archive-transfer is not rebound to current vaultsync trust")
        need(state["services"]["ledger-client"]["status"]=="running","ledger-client is not restored")
        need(state["services"]["vault-health"]["status"]=="running","approved vault-health workflow was disrupted")
        rp=state["services"]["reporting-api"]
        need(rp["status"]=="running" and rp["principal"]=="CORP\\svc_reporting" and rp["credential_version"]==4,"clean reporting workflow was disrupted")
    except (KeyError,TypeError) as exc:
        problem("recovery",f"service state incomplete: {exc}");return False
    return ok

def exact_fields(obj,expected,area):
    if not isinstance(obj,dict):problem(area,"finding must be a JSON object");return False
    got=set(obj);expected=set(expected)
    if got!=expected:
        problem(area,f"finding fields must be exactly {sorted(expected)}; got {sorted(got)}");return False
    return True

def check_scope(report):
    root={"case_id","affected_hosts","initial_access","lateral_movement","persistence","timeline","indicators"}
    if not exact_fields(report,root,"scope"):return False
    ok=True
    if report.get("case_id")!="FIN-2025-0417":ok=False;problem("scope","case_id is missing or does not match the supplied case")
    hosts=report.get("affected_hosts")
    if not isinstance(hosts,list) or not all(isinstance(x,str) for x in hosts):problem("scope","affected_hosts must be a list of host-name strings");return False
    vals={x.casefold() for x in hosts}
    if len(vals)!=len(hosts) or vals!=HOSTS:ok=False;problem("scope",f"affected scope must contain every evidence-supported compromised host exactly once; got {sorted(vals)}")
    return ok

def check_initial(report):
    obj=report.get("initial_access") if isinstance(report,dict) else None
    expected={"host","vector","execution","assessment","evidence"}
    if not exact_fields(obj,expected,"initial"):return False
    ok=True
    values={"host":"acct-ws-04","vector":"malicious_document","execution":"powershell","assessment":"confirmed_compromise"}
    for key,value in values.items():
        if str(obj.get(key,"")).casefold()!=value:ok=False;problem("initial",f"{key} does not match the evidence-supported controlled finding")
    paths,segments,c_ok=citations(obj,"initial");ok &= c_ok
    gpaths,gsegments=selected_evidence(report)
    fam={family(p) for p in paths|gpaths};blob=evidence_text(segments+gsegments)
    if "alert" not in fam:ok=False;problem("initial","initial access must cite the endpoint alert record")
    if not contains_all(blob,"acct-ws-04","powershell","winword.exe","198.51.100.77",MAL_SHA):ok=False;problem("initial","cited record does not bind host, Office parent, execution, download address, and payload")
    return bool(ok)

def check_lateral(report):
    items=report.get("lateral_movement") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("lateral","lateral_movement must be a list");return False
    expected={"source","destination","account","channel","assessment","evidence"}
    gpaths,gsegments=selected_evidence(report);gfam={family(p) for p in gpaths};gblob=evidence_text(gsegments)
    found={"workstation_to_gateway":0,"gateway_to_vault":0};seen=set();ok=True
    for i,item in enumerate(items):
        area=f"lateral[{i}]"
        if not exact_fields(item,expected,area):ok=False;continue
        paths,segments,c_ok=citations(item,area);ok &= c_ok
        fam={family(p) for p in paths}|gfam;blob=evidence_text(segments)+"\n"+gblob
        identity=(str(item.get("source","")).casefold(),str(item.get("destination","")).casefold(),str(item.get("account","")).casefold())
        if identity in seen:ok=False;problem(area,"duplicate lateral-movement finding")
        seen.add(identity)
        if item.get("channel")!="ssh" or item.get("assessment")!="confirmed_compromise":ok=False;problem(area,"controlled channel/assessment labels do not match the evidence")
        relevant=fam & {"windows-security","sysmon","linux-auth","linux-audit","network"}
        if len(relevant)<2:ok=False;problem(area,"causal chain needs two independent endpoint/auth/network source families")
        if identity==("acct-ws-04","backup-gw-02",r"corp\backupsvc"):
            found["workstation_to_gateway"]+=1
            if not contains_all(blob,"10.24.8.17","10.24.5.20","backup-gw-02","backupsvc") or not any(x in blob for x in ("ssh","port 51812",",22,")):ok=False;problem(area,"records do not bind the workstation-to-gateway SSH hop")
        elif identity==("backup-gw-02","vault-prx-03",r"corp\vaultsync"):
            found["gateway_to_vault"]+=1
            if not contains_all(blob,"10.24.5.20","10.24.9.31","backup-gw-02","vault-prx-03","vaultsync") or not any(x in blob for x in ("ssh","port 49221",",22,")):ok=False;problem(area,"records do not bind the gateway-to-vault SSH hop")
        else:ok=False;problem(area,"source, destination, or account does not match an evidence-supported compromise hop")
    if found!={"workstation_to_gateway":1,"gateway_to_vault":1}:ok=False;problem("lateral",f"the complete two-hop chain is required exactly once; got {found}")
    return bool(ok)


def check_persistence(report):
    items=report.get("persistence") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("persistence","persistence must be a list");return False
    expected={"host","kind","object","effect","assessment","evidence"};found={"run":0,"gateway_unit":0,"gateway_key":0,"vault_unit":0,"vault_key":0};seen=set();ok=True
    gpaths,gsegments=selected_evidence(report);gfam={family(p) for p in gpaths};gblob=evidence_text(gsegments)
    for i,item in enumerate(items):
        area=f"persistence[{i}]"
        if not exact_fields(item,expected,area):ok=False;continue
        paths,segments,c_ok=citations(item,area);fam={family(p) for p in paths}|gfam;blob=evidence_text(segments)+"\n"+gblob;ok &= c_ok
        host=str(item["host"]).casefold();kind=item["kind"];obj=str(item["object"]);objlow=obj.casefold();effect=item["effect"];assessment=item["assessment"]
        identity=(host,kind,objlow,effect,assessment)
        if identity in seen:ok=False;problem(area,"duplicate finding")
        seen.add(identity)
        if host=="acct-ws-04" and kind=="registry_run" and objlow=="onedrivehealth" and effect=="execution" and assessment=="malicious":
            found["run"]+=1
            if not (fam & {"alert","registry"}) or not contains_all(blob,"onedrivehealth",r"c:\programdata\onedrivehealth\update.ps1"):ok=False;problem(area,"Run finding is not bound to its captured payload")
        elif host=="backup-gw-02" and kind=="systemd_service" and objlow in {"cert-cache.service","/etc/systemd/system/cert-cache.service","/opt/cache/cert_sync.py"} and effect=="execution" and assessment=="malicious":
            found["gateway_unit"]+=1
            if "filesystem" not in fam or not (fam & {"memory-process","memory-socket","linux-audit","network"}) or not contains_all(blob,r"/opt/cache/cert_sync.py","203.0.113.201"):ok=False;problem(area,"service finding lacks filesystem plus runtime/socket support")
        elif host=="backup-gw-02" and kind=="ssh_authorized_key" and obj in {ROGUE_FP,"deploy@acct-ws-04"} and effect=="reentry" and assessment=="malicious":
            found["gateway_key"]+=1
            if "filesystem" not in fam or not (fam & {"cmdb","linux-auth","linux-audit"}) or not contains_all(blob,"deploy@acct-ws-04",ROGUE_FP,"SHA256:f0nRq8M0P4KxZ3TSxq1U7vWlYVzwQbQzdN0cP6q2Y9A"):ok=False;problem(area,"key finding lacks captured key plus approved/auth support")
        elif host=="vault-prx-03" and kind=="systemd_service" and objlow in {"index-cache.service","/etc/systemd/system/index-cache.service","/usr/local/libexec/.index-cache"} and effect=="execution" and assessment=="malicious":
            found["vault_unit"]+=1
            if "filesystem" not in fam or not (fam & {"memory-process","memory-socket","linux-audit","network"}) or not contains_all(blob,"/usr/local/libexec/.index-cache","198.51.100.203"):ok=False;problem(area,"vault service finding lacks filesystem plus runtime/socket support")
        elif host=="vault-prx-03" and kind=="ssh_authorized_key" and obj in {ROGUE2_FP,"cache-maint@backup-gw-02"} and effect=="reentry" and assessment=="malicious":
            found["vault_key"]+=1
            if "filesystem" not in fam or not (fam & {"cmdb","linux-auth","linux-audit"}) or not contains_all(blob,"cache-maint@backup-gw-02",ROGUE2_FP,APPROVED2_FP):ok=False;problem(area,"vault key finding lacks captured key plus approved/auth support")
        elif host=="acct-ws-04" and kind=="scheduled_task" and objlow in {"task-44","financemonthend",r"c:\program files\ledger\monthend.ps1"} and effect=="execution" and assessment=="benign":
            if "cmdb" not in fam or not (fam & {"registry","filesystem"}) or not any(x in blob for x in ("task-44","financemonthend","finance-owned signed export")):ok=False;problem(area,"benign month-end finding lacks baseline plus captured-config support")
        elif host=="backup-gw-02" and kind=="systemd_timer" and objlow in {"timer-12","vendor-inventory.timer"} and effect=="execution" and assessment=="benign":
            if "cmdb" not in fam or "filesystem" not in fam or not any(x in blob for x in ("timer-12","vendor-inventory")):ok=False;problem(area,"benign vendor timer lacks baseline plus captured-unit support")
        elif host=="backup-gw-02" and kind=="ssh_authorized_key" and obj in {"SHA256:f0nRq8M0P4KxZ3TSxq1U7vWlYVzwQbQzdN0cP6q2Y9A","ops@vault"} and effect=="reentry" and assessment=="benign":
            if "cmdb" not in fam or "filesystem" not in fam or not contains_all(blob,"ops@vault","SHA256:f0nRq8M0P4KxZ3TSxq1U7vWlYVzwQbQzdN0cP6q2Y9A"):ok=False;problem(area,"managed-key finding lacks baseline plus captured-key support")
        elif host=="vault-prx-03" and kind=="systemd_service" and objlow in {"unit-92","vault-health.service","/usr/local/bin/vault-health"} and effect=="execution" and assessment=="benign":
            if "cmdb" not in fam or "filesystem" not in fam or not contains_all(blob,"vault-health","203.0.113.88"):ok=False;problem(area,"benign vault-health finding lacks baseline plus captured-unit support")
        elif host=="vault-prx-03" and kind=="ssh_authorized_key" and obj in {APPROVED2_FP,"archive-admin@corp"} and effect=="reentry" and assessment=="benign":
            if "cmdb" not in fam or "filesystem" not in fam or not contains_all(blob,"archive-admin@corp",APPROVED2_FP):ok=False;problem(area,"managed vault-key finding lacks baseline plus captured-key support")
        else:
            ok=False;problem(area,"controlled finding fields do not describe an evidence-supported malicious or benign persistence object")
    required={"run":1,"gateway_unit":1,"gateway_key":1,"vault_unit":1,"vault_key":1}
    if found!=required:ok=False;problem("persistence",f"each malicious execution/re-entry finding is required exactly once; got {found}")
    return bool(ok)

def parse_time(value):
    if not isinstance(value,str):raise ValueError
    parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    if parsed.tzinfo is None:raise ValueError
    return parsed

def check_timeline(report):
    items=report.get("timeline") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("timeline","timeline must be a list");return False
    expected={"time_utc","kind","evidence"}
    windows={
      "initial_execution":("2025-04-17T09:12:00+00:00","2025-04-17T09:13:30+00:00"),
      "credential_access":("2025-04-17T09:16:00+00:00","2025-04-17T09:17:30+00:00"),
      "lateral_access":("2025-04-17T09:18:00+00:00","2025-04-17T09:25:00+00:00"),
      "persistence_activation":("2025-04-17T09:19:00+00:00","2025-04-17T09:27:00+00:00")}
    counts={k:0 for k in windows};seen_events=set();ok=True
    for i,item in enumerate(items):
        area=f"timeline[{i}]"
        if not exact_fields(item,expected,area):ok=False;continue
        kind=item.get("kind");paths,segments,c_ok=citations(item,area);ok &= c_ok
        if kind not in windows:ok=False;problem(area,"unknown lifecycle kind");continue
        try:t=parse_time(item.get("time_utc"))
        except Exception:ok=False;problem(area,"invalid timezone-aware ISO-8601 time");continue
        blob=evidence_text(segments);submitted=str(item["time_utc"]).replace("+00:00","Z")
        if submitted.casefold() not in blob and str(item["time_utc"]).casefold() not in blob:ok=False;problem(area,"timestamp does not occur in the selected source record");continue
        lo=parse_time(windows[kind][0]);hi=parse_time(windows[kind][1])
        if lo<=t<=hi:
            event_key=(kind,t.isoformat())
            if event_key in seen_events:ok=False;problem(area,"duplicate lifecycle event")
            else:seen_events.add(event_key);counts[kind]+=1
        else:ok=False;problem(area,"timestamp is outside its supporting evidence interval")
    required_counts={"initial_execution":1,"credential_access":1,"lateral_access":2,"persistence_activation":1}
    if any(counts[k]<v for k,v in required_counts.items()):ok=False;problem("timeline",f"each lifecycle stage and each distinct lateral hop require supported events; got {counts}")
    return bool(ok)

def check_indicators(report):
    items=report.get("indicators") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("indicators","indicators must be a list");return False
    expected_fields={"type","value","disposition","evidence"}
    expected={"198.51.100.77":("ip","hostile"),"203.0.113.201":("ip","hostile"),"198.51.100.203":("ip","hostile"),MAL_SHA:("sha256","hostile"),RELAY_SHA:("sha256","hostile"),VAULT_SHA:("sha256","hostile"),ROGUE_FP:("key_fingerprint","hostile"),ROGUE2_FP:("key_fingerprint","hostile"),"192.0.2.44":("ip","approved"),"203.0.113.88":("ip","approved"),APPROVED_FP:("key_fingerprint","approved"),APPROVED2_FP:("key_fingerprint","approved"),VENDOR_SHA:("sha256","approved"),VAULT_APPROVED_SHA:("sha256","approved")}
    required=BAD_IPS|{MAL_SHA,RELAY_SHA,VAULT_SHA,ROGUE_FP,ROGUE2_FP};seen=set();ok=True
    for i,item in enumerate(items):
        area=f"indicators[{i}]"
        if not exact_fields(item,expected_fields,area):ok=False;continue
        paths,segments,c_ok=citations(item,area);ok &= c_ok
        value=str(item["value"]);seen.add(value);blob=evidence_text(segments)
        if value not in expected:ok=False;problem(area,"indicator is not supported by the case trust/behavior evidence");continue
        itype,disp=expected[value]
        if item["type"]!=itype or item["disposition"]!=disp:ok=False;problem(area,"controlled indicator type/disposition does not match evidence")
        if value.casefold() not in blob:ok=False;problem(area,"indicator value does not occur in its selected source record")
    if not required<=seen:ok=False;problem("indicators",f"trusted hostile indicator set is incomplete: {sorted(required-seen)}")
    if any(sum(1 for x in items if isinstance(x,dict) and str(x.get("value"))==v)>1 for v in seen):ok=False;problem("indicators","duplicate indicator entries are not accepted")
    return bool(ok)

def main():
    state=load_json(STATE,"state"); report=load_json(REPORT,"report")
    checks={
      "eradication_and_containment":check_state(state),
      "service_recovery":check_recovery(state),
      "scope":check_scope(report),
      "initial_access":check_initial(report),
      "lateral_movement":check_lateral(report),
      "persistence":check_persistence(report),
      "timeline":check_timeline(report),
      "indicators":check_indicators(report)}
    D["subscores"]={k:int(v) for k,v in checks.items()}
    D["reward"]=1.0 if all(checks.values()) else 0.0
    LOGDIR.mkdir(parents=True,exist_ok=True)
    (LOGDIR/"reward.txt").write_text(f"{D['reward']}\n")
    (LOGDIR/"details.json").write_text(json.dumps(D,indent=2,sort_keys=True)+"\n")
    print(json.dumps(D,indent=2,sort_keys=True))
    return 0 if D["reward"]==1.0 else 1

if __name__=="__main__":raise SystemExit(main())
