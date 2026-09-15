#!/usr/bin/env python3
"""Semantic verifier for the defensive multi-artifact response outcome."""
from __future__ import annotations
import datetime as dt
import csv
import json
import os
import re
import shlex
from pathlib import Path

STATE=Path(os.environ.get("IR_STATE","/case/live/state.json"))
REPORT=Path(os.environ.get("IR_REPORT","/app/incident_report.json"))
# The verifier reads its own supplied fixture, never solver-writable evidence.
EVIDENCE=Path(__file__).resolve().parent/"fixtures"/"evidence"
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
D={"reward":0.0,"subscores":{},"problems":[],"metrics":{}}

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
        if p.is_symlink() or not p.is_file():return False,f"cited artifact does not exist: {rel}",None,None
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

def selected_records(report):
    """Resolve citations into typed records, retaining host and record identity.

    A locator in a pretty-printed JSON baseline identifies the smallest enclosing
    object, so a fingerprint remains attached to its host and principal.
    """
    records={}
    def walk(value):
        if isinstance(value,dict):
            if set(value)=={"path","locator"}:
                valid,_,path,line=citation(value)
                if not valid:return
                file=EVIDENCE/path; data={}
                if file.suffix==".jsonl":data=json.loads(line)
                elif file.suffix==".csv":
                    header=file.read_text().splitlines()[0]
                    data=next(csv.DictReader([header,line]))
                elif file.suffix==".json":
                    candidates=[]
                    def enclosing(obj):
                        if isinstance(obj,dict):
                            if value["locator"].casefold() in json.dumps(obj).casefold():candidates.append(obj)
                            for child in obj.values():enclosing(child)
                        elif isinstance(obj,list):
                            for child in obj:enclosing(child)
                    enclosing(json.loads(file.read_text()))
                    if candidates:data=min(candidates,key=lambda x:len(json.dumps(x)))
                host=data.get("host")
                if not host:
                    host=next((h for h in HOSTS|{"report-db-01"} if h in Path(path).parts or Path(path).name.startswith(h)),None)
                records[(path,line)]={"path":path,"line":line,"data":data,"host":host,"family":family(path)}
            else:
                for child in value.values():walk(child)
        elif isinstance(value,list):
            for child in value:walk(child)
    walk(report)
    return list(records.values())

HOPS=(("acct-ws-04","backup-gw-02",r"corp\backupsvc","10.24.8.17","10.24.5.20"),
      ("backup-gw-02","vault-prx-03",r"corp\vaultsync","10.24.5.20","10.24.9.31"))

def record_hops(record):
    """Return only hops whose endpoint/account fields agree within this record."""
    data=record["data"];line=record["line"].casefold();found=set()
    for source,destination,account,src_ip,dst_ip in HOPS:
        user=account.split("\\")[-1]; f=record["family"]
        network=(f=="network" and data.get("src_host")==source and data.get("dst_host")==destination
                 and data.get("src_ip")==src_ip and data.get("dst_ip")==dst_ip and data.get("dst_port")=="22")
        auth=(f=="linux-auth" and record["host"]==destination and f"accepted publickey for {user} from {src_ip} " in line)
        explicit=(f=="windows-security" and data.get("host")==source and data.get("target_server")==destination
                  and str(data.get("target_account","")).casefold()==account and data.get("source_ip")==src_ip)
        execution=(f in {"linux-audit","sysmon"} and record["host"]==source
                   and re.search(r"\bssh\s",str(data.get("command",data.get("command_line",""))).casefold())
                   and any(f"{user}@{target}" in line for target in (destination,dst_ip)))
        if network or auth or explicit or execution:found.add((source,destination,account))
    return found

def corroborated_hop(records,identity):
    matched=[r for r in records if identity in record_hops(r)]
    families={r["family"] for r in matched}
    # Flow observations establish endpoints/protocol; endpoint observations bind
    # the principal. Neither unrelated traffic nor a second hop can corroborate.
    return len(families)>=2 and bool(families-{"network"}) and bool(families & {"linux-auth","linux-audit","network","sysmon"})

def service_support(records,host,payload,c2):
    local=[r for r in records if r["host"]==host]
    units=[r for r in local if r["family"]=="filesystem" and r["path"].endswith(".service")
           and "execstart=" in r["line"].casefold() and payload in r["line"]]
    processes=[r for r in local if r["family"]=="memory-process" and payload in command_words(r["data"].get("command_line",""))]
    # The public contract permits independent runtime evidence instead of a
    # filesystem capture. Bind the named unit's activation to its known payload
    # running under the service manager on the same host, after activation.
    unit={"backup-gw-02":"cert-cache.service","vault-prx-03":"index-cache.service"}.get(host)
    for record in local:
        data=record["data"]; words=command_words(data.get("command",""))
        if (record["family"]!="linux-audit" or data.get("exe")!="/usr/bin/systemctl"
                or len(words)<3 or Path(words[0]).name!="systemctl" or words[1]!="enable" or unit not in words[2:]):continue
        for process in processes:
            if str(process["data"].get("ppid"))!="1":continue
            try:
                if parse_time(process["data"]["start_time_utc"])>=parse_time(data["time_utc"]):return True
            except (KeyError,TypeError,ValueError):pass
    sockets=[r for r in local if r["family"]=="memory-socket" and str(r["data"].get("remote","")).rsplit(":",1)[0]==c2]
    if units and any(p["data"].get("pid")==s["data"].get("pid") for p in processes for s in sockets):return True
    # Equivalent static/runtime evidence: the captured payload itself binds its
    # destination, and a host audit/process record binds that payload to execution.
    captured=[r for r in local if r["family"]=="filesystem" and r["path"]==f"filesystem/{host}{payload}" and c2 in r["line"]]
    execution=processes or [r for r in local if r["family"]=="linux-audit" and payload in str(r["data"].get("command",""))]
    flows=[r for r in records if r["family"]=="network" and r["data"].get("src_host")==host
           and r["data"].get("dst_ip")==c2]
    return bool(units and execution and (captured or flows))

def command_words(command):
    try:return shlex.split(command) if isinstance(command,str) else []
    except ValueError:return []

def malicious_key_support(records,host,fingerprint,comment):
    """Bind a key to its host/account using independent persistence evidence.

    These normalized fingerprint/comment associations are also exposed in the
    public range inventory; synthetic key bytes are not a fingerprint oracle.
    No particular approved-key fingerprint has to appear in a submitted report.
    """
    identities={("backup-gw-02",ROGUE_FP):"deploy@acct-ws-04",
                ("vault-prx-03",ROGUE2_FP):"cache-maint@backup-gw-02"}
    if identities.get((host,fingerprint))!=comment:return False
    local=[r for r in records if r["host"]==host]
    captured=[r for r in local if r["family"]=="filesystem"
              and r["path"].endswith("/.ssh/authorized_keys")
              and len(r["line"].split())>=3 and r["line"].split()[-1]==comment
              and r["line"].split()[0].startswith("ssh-")]
    baseline=json.loads((EVIDENCE/"cmdb/assets.json").read_text())["approved_ssh_keys"]
    approved=[key for key in baseline if key["host"]==host]
    if any(key["fingerprint"]==fingerprint or key["comment"]==comment for key in approved):return False
    baseline_cited=any(r["family"]=="cmdb" and r["data"] in approved for r in local)
    if captured and baseline_cited:return True
    # Authentication identifies the actual key and account; a separate audit
    # observation establishes addition to that account's authorized_keys. Neither
    # an unrelated login nor a write to another account can corroborate it.
    for record in local:
        if record["family"]!="linux-auth" or fingerprint not in record["line"].split():continue
        match=re.search(r"Accepted publickey for (\S+) from ",record["line"])
        if not match:continue
        principal=match.group(1)
        if any(key_addition(r,principal) for r in local):return True
    for key in captured:
        key_path="/"+key["path"].split("/",2)[2]
        match=re.fullmatch(r"/home/([^/]+)/\.ssh/authorized_keys",key_path)
        if not match:continue
        principal=match.group(1)
        for record in local:
            data=record["data"]
            if (record["family"]=="linux-auth" and fingerprint in record["line"].split()
                    and f"Accepted publickey for {principal} from " in record["line"]):return True
            if key_addition(record,principal):return True
    return False

def key_addition(record,principal):
    data=record["data"]; path=f"/home/{principal}/.ssh/authorized_keys"
    return (record["family"]=="linux-audit" and data.get("auid")==principal
            and data.get("object")==path
            and bool(re.search(r">>\s*"+re.escape(path)+r"(?:\s|$)",str(data.get("command","")))))

def host_evidence(records,host):
    matched=[r for r in records if r["host"]==host or r["data"].get("src_host")==host]
    return {r["family"] for r in matched}, evidence_text(
        [r["line"]+"\n"+"\n".join(str(v) for v in r["data"].values()) for r in matched])

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

def mapping(value):
    return value if isinstance(value,dict) else {}

def summarize_requirements(metric):
    checks=metric["checks"]
    metric.update(passed=sum(c["passed"] for c in checks),total=len(checks),
                  evaluated=sum(c["status"]=="evaluated" for c in checks),
                  not_evaluated=sum(c["status"]=="not_evaluated" for c in checks))

def check_state(state):
    ok=True
    metric_name='eradication_and_preservation'
    results=[];D["metrics"]["eradication_and_preservation"]={"checks":results}
    def need(predicate,msg):
        nonlocal ok
        try: passed=bool(predicate()); status="evaluated"
        except (KeyError,TypeError,ValueError,AttributeError): passed=False; status="not_evaluated"
        results.append({"failure_message":msg,"passed":passed,"status":status})
        if not passed: ok=False; problem("recovery" if "service_recovery" in metric_name else "state",msg)
    state=mapping(state)
    ah=mapping(mapping(state.get('hosts')).get('acct-ws-04')); bh=mapping(mapping(state.get('hosts')).get('backup-gw-02'))
    vh=mapping(mapping(state.get('hosts')).get('vault-prx-03')); db=mapping(mapping(state.get('hosts')).get('report-db-01'))
    need(lambda: not ah["startup_entries"]["HKCU-17"]["enabled"],"alerted registry startup still enabled")
    need(lambda: ah["artifacts"]["FILE-221"]["quarantined"],"alerted PowerShell payload not quarantined")
    need(lambda: not bh["startup_entries"]["UNIT-77"]["enabled"],"backup gateway systemd persistence still enabled")
    need(lambda: bh["artifacts"]["FILE-914"]["quarantined"],"backup gateway relay payload not quarantined")
    need(lambda: not bh["ssh_keys"]["KEY-88"]["present"],"unauthorized backup gateway key still present")
    need(lambda: not vh["startup_entries"]["UNIT-93"]["enabled"],"vault proxy systemd persistence still enabled")
    need(lambda: vh["artifacts"]["FILE-931"]["quarantined"],"vault proxy relay payload not quarantined")
    need(lambda: not vh["ssh_keys"]["KEY-94"]["present"],"unauthorized vault proxy key still present")
    need(lambda: bh["ssh_keys"]["KEY-73"]["present"],"managed backup-gateway SSH key was removed")
    need(lambda: vh["ssh_keys"]["KEY-91"]["present"],"managed vault-proxy SSH key was removed")
    need(lambda: ah["startup_entries"]["TASK-44"]["enabled"],"legitimate month-end task was disabled")
    need(lambda: not ah["artifacts"]["FILE-310"]["quarantined"],"legitimate ledger script was quarantined")
    need(lambda: bh["startup_entries"]["TIMER-12"]["enabled"],"approved inventory timer was disabled")
    need(lambda: not bh["artifacts"]["FILE-701"]["quarantined"],"approved inventory binary was quarantined")
    need(lambda: vh["startup_entries"]["UNIT-92"]["enabled"],"approved vault-health service was disabled")
    need(lambda: not vh["artifacts"]["FILE-930"]["quarantined"],"approved vault-health binary was quarantined")
    need(lambda: db["startup_entries"]["DB-11"]["enabled"] and not db["artifacts"]["DBFILE-1"]["quarantined"],"clean reporting host was altered")
    need(lambda: not state["sessions"]["S-4101"]["active"],"incident backupsvc session remains active")
    need(lambda: not state["sessions"]["S-4302"]["active"],"incident vaultsync session remains active")
    need(lambda: state["sessions"]["S-6200"]["active"],"legitimate reporting session was revoked")
    backup=mapping(mapping(state.get('credentials')).get('CORP\\backupsvc')); vault=mapping(mapping(state.get('credentials')).get('CORP\\vaultsync'))
    reporting=mapping(mapping(state.get('credentials')).get('CORP\\svc_reporting'))
    need(lambda: backup["rotated"] and backup["version"]>7,"exposed backupsvc credential was not rotated")
    need(lambda: vault["rotated"] and vault["version"]>2,"exposed vaultsync credential was not rotated")
    need(lambda: not reporting["rotated"] and reporting["version"]==4,"unexposed reporting credential was rotated")
    need(lambda: BAD_IPS<=set(state["blocked_indicators"]),"trusted hostile network indicators are not all blocked")
    need(lambda: not (APPROVED_IPS & set(state["blocked_indicators"])),"an approved partner destination was blocked")
    summarize_requirements(D["metrics"][metric_name])
    return ok

def check_recovery(state):
    ok=True
    metric_name='service_recovery'
    results=[];D["metrics"]["service_recovery"]={"checks":results}
    def need(predicate,msg):
        nonlocal ok
        try: passed=bool(predicate()); status="evaluated"
        except (KeyError,TypeError,ValueError,AttributeError): passed=False; status="not_evaluated"
        results.append({"failure_message":msg,"passed":passed,"status":status})
        if not passed: ok=False; problem("recovery" if "service_recovery" in metric_name else "state",msg)
    state=mapping(state)
    b=mapping(mapping(state.get('credentials')).get('CORP\\backupsvc')); v=mapping(mapping(state.get('credentials')).get('CORP\\vaultsync'))
    nb=mapping(mapping(state.get('services')).get('nightly-backup'))
    need(lambda: nb["status"]=="running","nightly-backup is not running")
    need(lambda: nb["host"]=="backup-gw-02" and nb["principal"]=="CORP\\backupsvc" and nb["credential_version"]==b["version"],"nightly-backup is not rebound to current backupsvc trust")
    at=mapping(mapping(state.get('services')).get('archive-transfer'))
    need(lambda: at["status"]=="running","archive-transfer is not running")
    need(lambda: at["host"]=="vault-prx-03" and at["principal"]=="CORP\\vaultsync" and at["credential_version"]==v["version"],"archive-transfer is not rebound to current vaultsync trust")
    need(lambda: state["services"]["ledger-client"]["status"]=="running","ledger-client is not restored")
    need(lambda: state["services"]["vault-health"]["status"]=="running","approved vault-health workflow was disrupted")
    rp=mapping(mapping(state.get('services')).get('reporting-api'))
    need(lambda: rp["status"]=="running" and rp["principal"]=="CORP\\svc_reporting" and rp["credential_version"]==4,"clean reporting workflow was disrupted")
    summarize_requirements(D["metrics"][metric_name])
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
    fam,blob=host_evidence(selected_records(report),"acct-ws-04")
    if "alert" not in fam:ok=False;problem("initial","initial access must cite the endpoint alert record")
    if not contains_all(blob,"acct-ws-04","powershell","winword.exe","198.51.100.77",MAL_SHA):ok=False;problem("initial","cited record does not bind host, Office parent, execution, download address, and payload")
    return bool(ok)

def check_lateral(report):
    items=report.get("lateral_movement") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("lateral","lateral_movement must be a list");return False
    expected={"source","destination","account","channel","assessment","evidence"}
    records=selected_records(report)
    found={"workstation_to_gateway":0,"gateway_to_vault":0};seen=set();ok=True
    for i,item in enumerate(items):
        area=f"lateral[{i}]"
        if not exact_fields(item,expected,area):ok=False;continue
        paths,segments,c_ok=citations(item,area);ok &= c_ok
        fam={family(p) for p in paths};blob=evidence_text(segments)
        identity=(str(item.get("source","")).casefold(),str(item.get("destination","")).casefold(),str(item.get("account","")).casefold())
        if identity in seen:ok=False;problem(area,"duplicate lateral-movement finding")
        seen.add(identity)
        if item.get("channel")!="ssh" or item.get("assessment")!="confirmed_compromise":ok=False;problem(area,"controlled channel/assessment labels do not match the evidence")
        if not corroborated_hop(records,identity):
            ok=False;problem(area,"hop needs two source families joined on its endpoints and principal")
        if identity==("acct-ws-04","backup-gw-02",r"corp\backupsvc"):
            found["workstation_to_gateway"]+=1
        elif identity==("backup-gw-02","vault-prx-03",r"corp\vaultsync"):
            found["gateway_to_vault"]+=1
        else:ok=False;problem(area,"source, destination, or account does not match an evidence-supported compromise hop")
    if found!={"workstation_to_gateway":1,"gateway_to_vault":1}:ok=False;problem("lateral",f"the complete two-hop chain is required exactly once; got {found}")
    return bool(ok)


def check_persistence(report):
    items=report.get("persistence") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("persistence","persistence must be a list");return False
    expected={"host","kind","object","effect","assessment","evidence"};found={"run":0,"gateway_unit":0,"gateway_key":0,"vault_unit":0,"vault_key":0};seen=set();ok=True
    records=selected_records(report)
    for i,item in enumerate(items):
        area=f"persistence[{i}]"
        if not exact_fields(item,expected,area):ok=False;continue
        paths,segments,c_ok=citations(item,area);ok &= c_ok
        host=str(item["host"]).casefold();kind=item["kind"];obj=str(item["object"]);objlow=obj.casefold();effect=item["effect"];assessment=item["assessment"]
        fam,blob=host_evidence(records,host)
        identity=(host,kind,objlow,effect,assessment)
        if identity in seen:ok=False;problem(area,"duplicate finding")
        seen.add(identity)
        if host=="acct-ws-04" and kind=="registry_run" and objlow=="onedrivehealth" and effect=="execution" and assessment=="malicious":
            found["run"]+=1
            if not (fam & {"alert","registry"}) or not contains_all(blob,"onedrivehealth",r"c:\programdata\onedrivehealth\update.ps1"):ok=False;problem(area,"Run finding is not bound to its captured payload")
        elif host=="backup-gw-02" and kind=="systemd_service" and objlow in {"cert-cache.service","/etc/systemd/system/cert-cache.service","/opt/cache/cert_sync.py"} and effect=="execution" and assessment=="malicious":
            found["gateway_unit"]+=1
            if not service_support(records,host,"/opt/cache/cert_sync.py","203.0.113.201"):ok=False;problem(area,"service finding lacks joined unit/payload evidence from independent capture or runtime sources")
        elif host=="backup-gw-02" and kind=="ssh_authorized_key" and obj in {ROGUE_FP,"deploy@acct-ws-04"} and effect=="reentry" and assessment=="malicious":
            found["gateway_key"]+=1
            if not malicious_key_support(records,host,ROGUE_FP,"deploy@acct-ws-04"):ok=False;problem(area,"key finding lacks independent persistence evidence joined by host, account, and key")
        elif host=="vault-prx-03" and kind=="systemd_service" and objlow in {"index-cache.service","/etc/systemd/system/index-cache.service","/usr/local/libexec/.index-cache"} and effect=="execution" and assessment=="malicious":
            found["vault_unit"]+=1
            if not service_support(records,host,"/usr/local/libexec/.index-cache","198.51.100.203"):ok=False;problem(area,"vault service finding lacks joined unit/payload evidence from independent capture or runtime sources")
        elif host=="vault-prx-03" and kind=="ssh_authorized_key" and obj in {ROGUE2_FP,"cache-maint@backup-gw-02"} and effect=="reentry" and assessment=="malicious":
            found["vault_key"]+=1
            if not malicious_key_support(records,host,ROGUE2_FP,"cache-maint@backup-gw-02"):ok=False;problem(area,"vault key finding lacks independent persistence evidence joined by host, account, and key")
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

def event_kinds(record):
    """Classify the selected observation, not its position in a time window."""
    data=record["data"]; f=record["family"]; host=record["host"]
    text="\n".join(str(v) for v in data.values()).casefold()
    kinds=set()
    if host=="acct-ws-04":
        if (f=="alert" and str(data.get("parent","")).casefold()=="winword.exe"
                and "powershell" in str(data.get("process","")).casefold()):kinds.add("initial_execution")
        if f=="sysmon" and data.get("destination_ip")=="198.51.100.77":kinds.add("initial_execution")
        if ((f=="windows-security" and data.get("event_id") in {4648,5140})
                or (f=="sysmon" and "get-content" in text and "backup-job.xml" in text)):
            kinds.add("credential_access")
        if f=="alert" and "registry_path" in data and data.get("value_name")=="OneDriveHealth":kinds.add("persistence_activation")
    hops=record_hops(record)
    if hops and f!="windows-security":kinds.add("lateral_access")
    payloads={"backup-gw-02":("/opt/cache/cert_sync.py","cert-cache.service"),
              "vault-prx-03":("/usr/local/libexec/.index-cache","index-cache.service")}
    if host in payloads:
        payload,unit=payloads[host]
        if f=="linux-audit":
            command=str(data.get("command","")).casefold()
            if ((data.get("exe")=="/usr/bin/install" and payload in command)
                    or (data.get("exe")=="/usr/bin/systemctl" and "enable" in command and unit in command)
                    or ("authorized_keys" in command and ">>" in command)):
                kinds.add("persistence_activation")
        if f=="memory-process" and payload in str(data.get("command_line","")):
            kinds.add("persistence_activation")
    return kinds,hops

def record_times(record):
    times=set()
    # Normalize timestamps before comparison, accepting equivalent UTC spellings.
    for value in re.findall(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)",record["line"]):
        try:times.add(parse_time(value))
        except ValueError:pass
    return times

def check_timeline(report):
    items=report.get("timeline") if isinstance(report,dict) else None
    if not isinstance(items,list):problem("timeline","timeline must be a list");return False
    expected={"time_utc","kind","evidence"}
    counts={k:0 for k in ("initial_execution","credential_access","lateral_access","persistence_activation")}
    seen_events=set();covered_hops=set();ok=True;event_results=[]
    for i,item in enumerate(items):
        area=f"timeline[{i}]"
        if not exact_fields(item,expected,area):ok=False;continue
        kind=item.get("kind");paths,segments,c_ok=citations(item,area);ok &= c_ok
        if kind not in counts:ok=False;problem(area,"unknown lifecycle kind");continue
        try:t=parse_time(item.get("time_utc"))
        except Exception:ok=False;problem(area,"invalid timezone-aware ISO-8601 time");continue
        supporting=[r for r in selected_records(item) if t in record_times(r) and kind in event_kinds(r)[0]]
        event_key=(kind,t.astimezone(dt.timezone.utc).isoformat())
        valid=c_ok and bool(supporting) and event_key not in seen_events
        event_results.append({"index":i,"kind":kind,"passed":valid})
        if not supporting:ok=False;problem(area,"selected timestamp and event behavior do not support the lifecycle finding")
        elif event_key in seen_events:ok=False;problem(area,"duplicate lifecycle event")
        else:
            seen_events.add(event_key);counts[kind]+=1
            if kind=="lateral_access":
                for record in supporting:covered_hops.update(event_kinds(record)[1])
    required_counts={"initial_execution":1,"credential_access":1,"lateral_access":2,"persistence_activation":1}
    if any(counts[k]<v for k,v in required_counts.items()):ok=False;problem("timeline",f"each lifecycle stage and each distinct lateral hop require supported events; got {counts}")
    expected_hops={hop[:3] for hop in HOPS}
    if covered_hops!=expected_hops:ok=False;problem("timeline","timeline must support each distinct source/destination/principal hop")
    D["metrics"]["timeline"]={"events":event_results,"covered_hops":len(covered_hops),"required_hops":len(expected_hops)}
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
    D["metrics"]["semantic_groups"]={"passed":sum(bool(v) for v in checks.values()),"total":len(checks)}
    D["reward"]=1.0 if all(checks.values()) else 0.0
    LOGDIR.mkdir(parents=True,exist_ok=True)
    (LOGDIR/"reward.txt").write_text(f"{D['reward']}\n")
    (LOGDIR/"details.json").write_text(json.dumps(D,indent=2,sort_keys=True)+"\n")
    print(json.dumps(D,indent=2,sort_keys=True))
    return 0 if D["reward"]==1.0 else 1

if __name__=="__main__":raise SystemExit(main())
