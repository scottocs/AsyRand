"""Account complete serialized messages by protocol function, without double counting."""
import json
import re

RBC = "asyrand/rbc/v1/"
ABA = "asyrand/quadratic-aba/v1/"
BEACON = "asyrand/beacon/v2/"
CORE = {"PRE", "VOTE", "MAIN", "FINAL"}
CERT = {"DECISION", "CERT_REQUEST", "CERT_RESPONSE"}
PARTS = ("producer", "aba_core", "aba_certificate", "aba_recovery", "reconstruction", "history_recovery")


def message_category(name):
    if name.startswith(RBC) and name[len(RBC):] in {"VAL", "ECHO", "READY", "REQUEST", "REPLY"}:
        return "producer"
    if name.startswith(ABA):
        typ = name[len(ABA):]
        if typ in CORE: return "aba_core"
        if typ in CERT: return "aba_certificate"
    if name.startswith(BEACON):
        typ = name[len(BEACON):]
        if typ in {"SYNC", "REPLAY"}: return "aba_recovery"
        if typ == "RECON": return "reconstruction"
        if typ in {"HISTORY", "REPLY"}: return "history_recovery"
    raise RuntimeError("unclassified message type: "+name)


def classify(data, window, expected_bytes):
    match = re.search(r"^"+re.escape(window)+r" message_metrics (.+)$", data, re.M)
    if not match: raise RuntimeError("missing classified traffic snapshot")
    types = json.loads(match[1])
    counts = dict.fromkeys(PARTS, 0)
    for name, values in types.items():
        counts[message_category(name)] += int(values["SentBytes"])
    total = sum(counts.values())
    if total != expected_bytes:
        raise RuntimeError(f"type totals differ from measurement window: {total} != {expected_bytes}")
    counts["aba"] = counts["aba_core"]+counts["aba_certificate"]+counts["aba_recovery"]
    counts["consumer"] = counts["aba"]+counts["reconstruction"]+counts["history_recovery"]
    counts["total"] = total
    assert counts["producer"]+counts["consumer"] == total
    return counts, types
