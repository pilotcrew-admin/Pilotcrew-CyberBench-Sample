#!/usr/bin/env python3
"""Reference investigation, eradication, and recovery workflow.

The solution joins independently produced artifacts before changing state. It
uses the same public response controls and citation contract available to a
human operator, then runs the public recovery diagnostic.
"""
from __future__ import annotations
import csv
import json
import os
import re
import subprocess
from pathlib import Path

E=Path(os.environ.get("IR_EVIDENCE","/evidence"))
STATE=Path(os.environ.get("IR_STATE","/case/live/state.json"))
REPORT=Path(os.environ.get("IR_REPORT","/app/incident_report.json"))

def jsonl(rel):
    return [json.loads(x) for x in (E/rel).read_text().splitlines() if x.strip()]

def rows(rel):
    with (E/rel).open(newline="") as f:return list(csv.DictReader(f))

def run(*args):
    print("+ irctl",*args)
    subprocess.run(["irctl",*args],check=True,env={**os.environ,"IR_STATE":str(STATE)})

def main():
    print("[1/5] Correlating endpoint execution and the alerted autostart")
    alerts=jsonl("alerts/edr_alerts.jsonl")
    high=next(x for x in alerts if x["severity"]=="high" and x["parent"].casefold().endswith("winword.exe"))
    reg_alert=next(x for x in alerts if x.get("registry_path"))
    sysmon=jsonl("windows/sysmon.jsonl")
    stage_net=next(x for x in sysmon if x.get("image","").casefold()=="powershell.exe" and x.get("destination_ip"))
    state=json.loads(STATE.read_text())
    acct=state["hosts"][high["host"]]
    run_id=next(i for i,v in acct["startup_entries"].items() if high["file_written"].casefold() in v["command"].casefold())
    alerted_file=next(i for i,v in acct["artifacts"].items() if v["sha256"]==high["file_sha256"])

    print("[2/5] Reconstructing credential use and lateral access")
    win=jsonl("windows/security_events.jsonl")
    explicit=next(x for x in win if x.get("event_id")==4648 and x.get("target_server"))
    account=explicit["target_account"]
    source=explicit["host"]; destination=explicit["target_server"]; source_ip=explicit["source_ip"]
    auth_lines=(E/"linux/backup-gw-02-auth.log").read_text().splitlines()
    remote_auth=next(x for x in auth_lines if source_ip in x and account.split("\\")[-1].casefold() in x.casefold())
    rogue_fp=re.search(r"SHA256:[A-Za-z0-9]+",remote_auth).group(0)
    flows=rows("network/flows.csv")
    lateral_flow=next(x for x in flows if x["src_host"]==source and x["dst_host"]==destination and x["dst_port"]=="22")
    session_id=next(i for i,v in state["sessions"].items() if v["principal"].casefold()==account.casefold() and v["source"]==source_ip)

    print("[3/5] Finding the silent runtime chain and unauthorized access")
    cmdb=json.loads((E/"cmdb/assets.json").read_text())
    approved_ips={x["ip"] for x in cmdb["approved_external_destinations"]}
    approved_fps={x["fingerprint"] for x in cmdb["approved_ssh_keys"] if x["host"]==destination}
    sockets=rows("memory/backup-gw-02-sockets.csv")
    suspicious_socket=next(x for x in sockets if x["remote"].rsplit(":",1)[0] not in approved_ips and x["process"]=="python3")
    c2_ip=suspicious_socket["remote"].rsplit(":",1)[0]
    processes=rows("memory/backup-gw-02-processes.csv")
    relay_proc=next(x for x in processes if x["pid"]==suspicious_socket["pid"])
    relay_path=next(part for part in relay_proc["command_line"].split() if part.startswith("/opt/"))
    bh=state["hosts"][destination]
    unit_id=next(i for i,v in bh["startup_entries"].items() if relay_path in v["command"])
    relay_file=next(i for i,v in bh["artifacts"].items() if v["path"]==relay_path and v["sha256"]==relay_proc["sha256"])
    rogue_key=next(i for i,v in bh["ssh_keys"].items() if v["fingerprint"] not in approved_fps)
    assert bh["ssh_keys"][rogue_key]["fingerprint"]==rogue_fp
    audit=jsonl("linux/backup-gw-02-audit.jsonl")
    pivot=next(x for x in audit if x.get("principal") and x.get("exe")=="/usr/bin/ssh")
    vault_account=pivot["principal"]
    vault_host=next(x["host"] for x in cmdb["assets"] if x["ip"] in pivot["command"])
    backup_ip=next(x["ip"] for x in cmdb["assets"] if x["host"]==destination)
    vault_ip=next(x["ip"] for x in cmdb["assets"] if x["host"]==vault_host)
    vault_auth_lines=(E/"linux/vault-prx-03-auth.log").read_text().splitlines()
    vault_remote_auth=next(x for x in vault_auth_lines if backup_ip in x and vault_account.split("\\")[-1].casefold() in x.casefold())
    vault_rogue_fp=re.search(r"SHA256:[A-Za-z0-9]+",vault_remote_auth).group(0)
    vault_flow=next(x for x in flows if x["src_host"]==destination and x["dst_host"]==vault_host and x["dst_port"]=="22")
    vault_session=next(i for i,v in state["sessions"].items() if v["principal"].casefold()==vault_account.casefold() and v["source"]==backup_ip)
    vault_approved_fps={x["fingerprint"] for x in cmdb["approved_ssh_keys"] if x["host"]==vault_host}
    vault_sockets=rows("memory/vault-prx-03-sockets.csv")
    vault_socket=next(x for x in vault_sockets if x["remote"].rsplit(":",1)[0] not in approved_ips)
    vault_c2=vault_socket["remote"].rsplit(":",1)[0]
    vault_processes=rows("memory/vault-prx-03-processes.csv")
    vault_proc=next(x for x in vault_processes if x["pid"]==vault_socket["pid"])
    vault_path=vault_proc["exe"]
    vh=state["hosts"][vault_host]
    vault_unit=next(i for i,v in vh["startup_entries"].items() if vault_path in v["command"])
    vault_file=next(i for i,v in vh["artifacts"].items() if v["path"]==vault_path and v["sha256"]==vault_proc["sha256"])
    vault_key=next(i for i,v in vh["ssh_keys"].items() if v["fingerprint"] not in vault_approved_fps)
    assert vh["ssh_keys"][vault_key]["fingerprint"]==vault_rogue_fp
    hostile_ips={stage_net["destination_ip"],c2_ip,vault_c2}-approved_ips

    print("[4/5] Applying surgical eradication, trust repair, and recovery")
    run("disable-startup",source,run_id)
    run("quarantine",source,alerted_file)
    run("disable-startup",destination,unit_id)
    run("quarantine",destination,relay_file)
    run("remove-key",destination,rogue_key)
    run("disable-startup",vault_host,vault_unit)
    run("quarantine",vault_host,vault_file)
    run("remove-key",vault_host,vault_key)
    run("revoke-session",session_id)
    run("revoke-session",vault_session)
    run("rotate-credential",account)
    run("rotate-credential",vault_account)
    run("rebind-service","nightly-backup",account)
    run("rebind-service","archive-transfer",vault_account)
    for ip in sorted(hostile_ips):run("block",ip)
    run("start-service",source,"ledger-client")
    run("start-service",destination,"nightly-backup")
    run("start-service",vault_host,"archive-transfer")

    print("[5/5] Writing an evidence-backed scope/timeline report")
    flow_locator=f'{lateral_flow["src_ip"]},{lateral_flow["src_host"]},{lateral_flow["dst_ip"]},{lateral_flow["dst_host"]},{lateral_flow["dst_port"]}'
    vault_flow_locator=f'{vault_flow["src_ip"]},{vault_flow["src_host"]},{vault_flow["dst_ip"]},{vault_flow["dst_host"]},{vault_flow["dst_port"]}'
    install=next(x for x in audit if relay_path in x.get("command",""))
    vault_audit=jsonl("linux/vault-prx-03-audit.jsonl")
    vault_install=next(x for x in vault_audit if x.get("exe")=="/usr/bin/systemctl" and "index-cache.service" in x.get("command",""))
    report={
      "case_id":state["case_id"],
      "affected_hosts":[source,destination,vault_host],
      "initial_access":{
        "host":source,"vector":"malicious_document","execution":"powershell","assessment":"confirmed_compromise",
        "evidence":[
          {"path":"alerts/edr_alerts.jsonl","locator":high["record_id"]},
          {"path":"windows/sysmon.jsonl","locator":stage_net["record_id"]}]},
      "lateral_movement":[
        {"source":source,"destination":destination,"account":account,"channel":"ssh","assessment":"confirmed_compromise",
         "evidence":[
          {"path":"windows/security_events.jsonl","locator":explicit["record_id"]},
          {"path":"linux/backup-gw-02-auth.log","locator":rogue_fp},
          {"path":"network/flows.csv","locator":flow_locator}]},
        {"source":destination,"destination":vault_host,"account":vault_account,"channel":"ssh","assessment":"confirmed_compromise",
         "evidence":[
          {"path":"linux/backup-gw-02-audit.jsonl","locator":pivot["record_id"]},
          {"path":"linux/vault-prx-03-auth.log","locator":vault_rogue_fp},
          {"path":"network/flows.csv","locator":vault_flow_locator}]}
      ],
      "persistence":[
        {"host":source,"kind":"registry_run","object":reg_alert["value_name"],"effect":"execution","assessment":"malicious",
         "evidence":[{"path":"alerts/edr_alerts.jsonl","locator":reg_alert["record_id"]},{"path":"registry/acct-ws-04.reg","locator":reg_alert["value_name"]}]},
        {"host":destination,"kind":"systemd_service","object":"cert-cache.service","effect":"execution","assessment":"malicious",
         "evidence":[{"path":"filesystem/backup-gw-02/etc/systemd/system/cert-cache.service","locator":f"ExecStart={relay_proc['command_line']}"},{"path":"memory/backup-gw-02-processes.csv","locator":relay_proc["sha256"]},{"path":"memory/backup-gw-02-sockets.csv","locator":c2_ip}]},
        {"host":destination,"kind":"ssh_authorized_key","object":rogue_fp,"effect":"reentry","assessment":"malicious",
         "evidence":[{"path":"filesystem/backup-gw-02/home/backupsvc/.ssh/authorized_keys","locator":"deploy@acct-ws-04"},{"path":"cmdb/assets.json","locator":next(iter(approved_fps))},{"path":"linux/backup-gw-02-auth.log","locator":rogue_fp},{"path":"linux/backup-gw-02-audit.jsonl","locator":"AUDIT-393"}]},
        {"host":vault_host,"kind":"systemd_service","object":"index-cache.service","effect":"execution","assessment":"malicious",
         "evidence":[{"path":"filesystem/vault-prx-03/etc/systemd/system/index-cache.service","locator":f"ExecStart={vault_proc['command_line']}"},{"path":"memory/vault-prx-03-processes.csv","locator":vault_proc["sha256"]},{"path":"memory/vault-prx-03-sockets.csv","locator":vault_c2}]},
        {"host":vault_host,"kind":"ssh_authorized_key","object":vault_rogue_fp,"effect":"reentry","assessment":"malicious",
         "evidence":[{"path":"filesystem/vault-prx-03/home/vaultsync/.ssh/authorized_keys","locator":"cache-maint@backup-gw-02"},{"path":"cmdb/assets.json","locator":next(iter(vault_approved_fps))},{"path":"linux/vault-prx-03-auth.log","locator":vault_rogue_fp},{"path":"linux/vault-prx-03-audit.jsonl","locator":"VAUDIT-773"}]}
      ],
      "timeline":[
        {"time_utc":high["time_utc"],"kind":"initial_execution","evidence":[{"path":"alerts/edr_alerts.jsonl","locator":high["record_id"]}]},
        {"time_utc":explicit["time_utc"],"kind":"credential_access","evidence":[{"path":"windows/security_events.jsonl","locator":explicit["record_id"]}]},
        {"time_utc":remote_auth.split()[0],"kind":"lateral_access","evidence":[{"path":"linux/backup-gw-02-auth.log","locator":rogue_fp}]},
        {"time_utc":vault_remote_auth.split()[0],"kind":"lateral_access","evidence":[{"path":"linux/vault-prx-03-auth.log","locator":vault_rogue_fp}]},
        {"time_utc":install["time_utc"],"kind":"persistence_activation","evidence":[{"path":"linux/backup-gw-02-audit.jsonl","locator":install["record_id"]}]},
        {"time_utc":vault_install["time_utc"],"kind":"persistence_activation","evidence":[{"path":"linux/vault-prx-03-audit.jsonl","locator":vault_install["record_id"]}]}
      ],
      "indicators":[
        {"type":"ip","value":stage_net["destination_ip"],"disposition":"hostile","evidence":[{"path":"windows/sysmon.jsonl","locator":stage_net["destination_ip"]}]},
        {"type":"ip","value":c2_ip,"disposition":"hostile","evidence":[{"path":"memory/backup-gw-02-sockets.csv","locator":c2_ip},{"path":"network/flows.csv","locator":c2_ip}]},
        {"type":"sha256","value":high["file_sha256"],"disposition":"hostile","evidence":[{"path":"alerts/edr_alerts.jsonl","locator":high["file_sha256"]}]},
        {"type":"sha256","value":relay_proc["sha256"],"disposition":"hostile","evidence":[{"path":"memory/backup-gw-02-processes.csv","locator":relay_proc["sha256"]},{"path":"memory/backup-gw-02-sockets.csv","locator":c2_ip}]},
        {"type":"key_fingerprint","value":rogue_fp,"disposition":"hostile","evidence":[{"path":"linux/backup-gw-02-auth.log","locator":rogue_fp},{"path":"cmdb/assets.json","locator":next(iter(approved_fps))}]},
        {"type":"ip","value":vault_c2,"disposition":"hostile","evidence":[{"path":"memory/vault-prx-03-sockets.csv","locator":vault_c2},{"path":"network/flows.csv","locator":vault_c2}]},
        {"type":"sha256","value":vault_proc["sha256"],"disposition":"hostile","evidence":[{"path":"memory/vault-prx-03-processes.csv","locator":vault_proc["sha256"]},{"path":"memory/vault-prx-03-sockets.csv","locator":vault_c2}]},
        {"type":"key_fingerprint","value":vault_rogue_fp,"disposition":"hostile","evidence":[{"path":"linux/vault-prx-03-auth.log","locator":vault_rogue_fp},{"path":"cmdb/assets.json","locator":next(iter(vault_approved_fps))}]}
      ]}
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    REPORT.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    run("verify")
    print(f"response complete; report written to {REPORT}")

if __name__=="__main__":main()
