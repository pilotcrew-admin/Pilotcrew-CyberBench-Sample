#!/usr/bin/env python3
"""Atomic response-range controls for the offline forensic task."""
from __future__ import annotations
import ipaddress
import json
import os
import sys
import tempfile
from pathlib import Path

STATE = Path(os.environ.get("IR_STATE", "/case/live/state.json"))

HELP = """usage: irctl COMMAND [ARGS]

commands:
  status
  quarantine HOST ARTIFACT_ID
  disable-startup HOST ENTRY_ID
  remove-key HOST KEY_ID
  revoke-session SESSION_ID
  rotate-credential PRINCIPAL
  rebind-service SERVICE_ID PRINCIPAL
  block INDICATOR
  start-service HOST SERVICE_ID
  verify
  help
"""

class CommandError(Exception):
    pass

def load():
    try:
        data=json.loads(STATE.read_text())
    except (OSError,json.JSONDecodeError) as exc:
        raise CommandError(f"cannot read valid state: {exc}")
    return data

def save(data):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=".state-",suffix=".json",dir=STATE.parent)
    try:
        with os.fdopen(fd,"w") as f:
            json.dump(data,f,indent=2,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(name,STATE)
        os.chmod(STATE,0o666)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass

def host(data,name):
    try:return data["hosts"][name]
    except KeyError:raise CommandError(f"unknown host: {name}")

def principal(data,name):
    matches=[p for p in data["credentials"] if p.casefold()==name.casefold()]
    if len(matches)!=1: raise CommandError(f"unknown principal: {name}")
    return matches[0]

def service(data,sid):
    try:return data["services"][sid]
    except KeyError:raise CommandError(f"unknown service: {sid}")

def require_arity(args,n,usage):
    if len(args)!=n: raise CommandError(f"usage: {usage}")

def verify(data):
    issues=[]
    for sid,svc in data["services"].items():
        if svc["status"]!="running": issues.append(f"service {sid} is not running")
        p=svc.get("principal")
        if p:
            current=data["credentials"].get(p,{}).get("version")
            if svc.get("credential_version")!=current:
                issues.append(f"service {sid} is bound to a stale credential version")
    if not data.get("blocked_indicators"):
        issues.append("no network indicators have been contained")
    return issues

def main(argv):
    if not argv or argv[0] in {"help","-h","--help"}:
        print(HELP); return 0
    cmd,args=argv[0],argv[1:]
    data=load(); changed=False
    if cmd=="status":
        require_arity(args,0,"irctl status")
        print(json.dumps(data,indent=2,sort_keys=True)); return 0
    if cmd=="quarantine":
        require_arity(args,2,"irctl quarantine HOST ARTIFACT_ID")
        h=host(data,args[0])
        if args[1] not in h["artifacts"]: raise CommandError(f"unknown artifact on {args[0]}: {args[1]}")
        h["artifacts"][args[1]]["quarantined"]=True; changed=True
    elif cmd=="disable-startup":
        require_arity(args,2,"irctl disable-startup HOST ENTRY_ID")
        h=host(data,args[0])
        if args[1] not in h["startup_entries"]: raise CommandError(f"unknown startup entry on {args[0]}: {args[1]}")
        h["startup_entries"][args[1]]["enabled"]=False; changed=True
    elif cmd=="remove-key":
        require_arity(args,2,"irctl remove-key HOST KEY_ID")
        h=host(data,args[0])
        if args[1] not in h["ssh_keys"]: raise CommandError(f"unknown key on {args[0]}: {args[1]}")
        h["ssh_keys"][args[1]]["present"]=False; changed=True
    elif cmd=="revoke-session":
        require_arity(args,1,"irctl revoke-session SESSION_ID")
        if args[0] not in data["sessions"]: raise CommandError(f"unknown session: {args[0]}")
        data["sessions"][args[0]]["active"]=False; changed=True
    elif cmd=="rotate-credential":
        require_arity(args,1,"irctl rotate-credential PRINCIPAL")
        p=principal(data,args[0]); cred=data["credentials"][p]
        if not cred.get("rotated"):
            cred["version"]+=1; cred["rotated"]=True
        changed=True
    elif cmd=="rebind-service":
        require_arity(args,2,"irctl rebind-service SERVICE_ID PRINCIPAL")
        svc=service(data,args[0]); p=principal(data,args[1])
        svc["principal"]=p; svc["credential_version"]=data["credentials"][p]["version"]; changed=True
    elif cmd=="block":
        require_arity(args,1,"irctl block INDICATOR")
        try: indicator=str(ipaddress.ip_address(args[0]))
        except ValueError: raise CommandError("INDICATOR must be a single IPv4 or IPv6 address")
        if indicator not in data["blocked_indicators"]: data["blocked_indicators"].append(indicator)
        changed=True
    elif cmd=="start-service":
        require_arity(args,2,"irctl start-service HOST SERVICE_ID")
        host(data,args[0]); svc=service(data,args[1])
        if svc["host"]!=args[0]: raise CommandError(f"service {args[1]} belongs to {svc['host']}, not {args[0]}")
        p=svc.get("principal")
        if p and svc.get("credential_version")!=data["credentials"][p]["version"]:
            raise CommandError(f"service {args[1]} has a stale credential binding; rebind it first")
        svc["status"]="running"; changed=True
    elif cmd=="verify":
        require_arity(args,0,"irctl verify")
        issues=verify(data)
        if issues:
            print("operator checks found issues:")
            for issue in issues: print(f"- {issue}")
            return 1
        print("operator safety and service-binding checks pass")
        return 0
    else:
        raise CommandError(f"unknown command: {cmd}\n{HELP}")
    if changed: save(data)
    print(json.dumps({"ok":True,"command":cmd},sort_keys=True))
    return 0

if __name__=="__main__":
    try: raise SystemExit(main(sys.argv[1:]))
    except CommandError as exc:
        print(f"irctl: {exc}",file=sys.stderr); raise SystemExit(2)
