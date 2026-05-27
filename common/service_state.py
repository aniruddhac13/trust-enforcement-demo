import datetime as dt
from typing import Dict, Any, List

def default_state() -> Dict[str, Any]:
    return {
        "events": [],
        "artifacts": {},
    }

def append_event(state: Dict[str, Any], service: str, action: str, status: str, details: Dict[str, Any]):
    state.setdefault("events", [])
    state["events"].append({
        "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "service": service,
        "action": action,
        "status": status,
        "details": details,
    })
    state["events"] = state["events"][-200:]
    return state
