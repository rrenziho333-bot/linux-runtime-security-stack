"""Evidence-based Lynis report scoring, separate from Lynis' hardening index."""

from collections import Counter
from pathlib import Path
import re
import time


CONTROL_ID = re.compile(r"^[A-Z]+-[0-9]+$")


def baseline_snapshot(state, now=None):
    result = dict(state.get("baseline_details") or {
        "status": state.get("baseline_status", "unavailable"), "score": state.get("posture_score")})
    now = time.time() if now is None else now
    if result.get("expires_at") and now > result["expires_at"]:
        result.update(status="unavailable", score=None, errors=["Lynis 报告已过期；检查 tsa-baseline.timer 或手动启动 tsa-baseline.service"])
    return result


def read_report(path: Path, require_complete=True):
    metadata, arrays = {}, {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = raw.strip().partition("=")
        if not sep or key.startswith("#"):
            continue
        if key.endswith("[]"):
            arrays.setdefault(key[:-2], []).append(value)
        else:
            metadata[key] = value
    if require_complete and (not metadata.get("report_version_major") or metadata.get("finish") != "true"):
        raise ValueError("Lynis report is incomplete or invalid")
    findings = []
    for kind in ("warning", "suggestion"):
        for raw in arrays.get(kind, []):
            parts = raw.split("|")
            if not parts[0].strip() or len(parts) < 2:
                raise ValueError("Malformed Lynis finding; cannot safely calculate baseline")
            findings.append({"type": kind.upper(), "control": parts[0],
                             "message": parts[1] if len(parts) > 1 else "",
                             "details": parts[2] if len(parts) > 2 else "",
                             "remediation": "|".join(parts[3:]), "raw": raw})
    details = []
    for raw in arrays.get("details", []):
        parts = raw.split("|")
        if len(parts) < 3:
            continue
        fields = {}
        for item in parts[2].split(";"):
            key, sep, value = item.partition(":")
            if sep:
                fields[key] = value
        details.append({"control": parts[0], "service": parts[1], **fields, "raw": raw})
    return {"metadata": metadata, "findings": findings, "details": details,
            "observations": {name: sorted(set(filter(None, arrays.get(key, [])))) for name, key in (
                ("vulnerable_packages", "vulnerable_package"),
                ("extra_uid_zero_accounts", "user_with_uid_zero"),
                ("passwordless_accounts", "account_without_password"))},
            "exceptions": arrays.get("exception_event", []),
            "executed": sorted(set(filter(None, metadata.get("tests_executed", "").split("|")))),
            "skipped": sorted(set(filter(None, metadata.get("tests_skipped", "").split("|"))))}


def points(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError("Baseline points must be integers between 0 and 100")
    return value


def score_report(report, config):
    """Count each control once; preserve even findings that do not affect score."""
    policies = config.get("controls")
    legacy = policies is None
    if legacy:
        selected = config.get("include_controls") or sorted({f["control"] for f in report["findings"]})
        deductions, defaults = config.get("deduct_by_control", {}), config.get("default_deduct", {})
        policies = {c: {"warning": deductions.get(c, defaults.get("warning", 0)),
                        "suggestion": deductions.get(c, defaults.get("suggestion", 0))
                        if config.get("scoring_mode") == "warnings_and_selected_suggestions" else 0,
                        "reason": "Legacy project policy"} for c in selected}
    if not isinstance(policies, dict):
        raise ValueError("baseline_lynis.controls must be a mapping")
    for control, policy in policies.items():
        if not CONTROL_ID.fullmatch(control) or not isinstance(policy, dict):
            raise ValueError("Invalid baseline control policy")
        for kind in ("warning", "suggestion"):
            points(policy.get(kind, 0))
        matches = policy.get("detail_matches", [])
        if not isinstance(matches, list):
            raise ValueError("Baseline detail_matches must be a list")
        for match in matches:
            if not isinstance(match, dict):
                raise ValueError("Invalid baseline detail matcher")
            points(match.get("points"))
            if not match.get("field") or not isinstance(match.get("values"), list) or not match.get("reason"):
                raise ValueError("Invalid baseline detail matcher")
    findings = [dict(f) for f in report["findings"]]
    executed, skipped = set(report["executed"]), set(report["skipped"])
    exception_controls = {s.split("|", 1)[0].split(":", 1)[0] for s in report["exceptions"]}
    controls, total = [], 0
    ids = sorted(set(policies) | executed | skipped | {f["control"] for f in findings} | exception_controls)
    for control in ids:
        policy = policies.get(control, {})
        candidates = [f for f in findings if f["control"] == control]
        evidence = [d for d in report["details"] if d["control"] == control]
        matched = []
        for detail in evidence:
            for match in policy.get("detail_matches", []):
                if detail.get("field", "").casefold() == match["field"].casefold() and \
                   detail.get("value", "").casefold() in [str(v).casefold() for v in match["values"]]:
                    matched.append({"points": match["points"], "reason": match["reason"], "evidence": detail})
        risk = max([points(policy.get(f["type"].lower(), 0)) for f in candidates]
                   + [m["points"] for m in matched] + [0])
        deducted = min(risk, 100 - total)
        total += deducted
        if control in exception_controls:
            status = "error"
        elif control in skipped:
            status = "skipped"
        elif candidates or matched:
            status = "finding"
        elif control in executed:
            status = "executed_no_finding"
        else:
            status = "unknown"
        reason = policy.get("reason", "未纳入自动计分，保留发现供人工审查")
        for f in candidates:
            f.update({"policy_points": points(policy.get(f["type"].lower(), 0)), "reason": reason})
        controls.append({"control": control, "title": policy.get("title", control), "status": status,
                         "selected": control in policies, "risk_points": risk, "deducted_points": deducted,
                         "reason": reason, "findings": candidates, "matched_details": matched,
                         "details": evidence})
    problems = []
    if config.get("require_execution_metadata") and not executed:
        problems.append("Missing Lynis tests_executed metadata; rerun a complete system audit")
    for control in config.get("required_controls", []):
        if control not in executed or control in skipped or control in exception_controls:
            problems.append(f"Required check {control} was not executed or reported an exception")
    for control in exception_controls & set(policies):
        if control not in config.get("required_controls", []) and (
            policies[control].get("warning") or policies[control].get("suggestion") or policies[control].get("detail_matches")
        ):
            problems.append(f"Scored check {control} reported an exception")
    metadata = report["metadata"]
    return {"status": "unavailable" if problems else "ok", "score": None if problems else 100 - total,
            "policy_version": config.get("policy_version", "legacy"), "errors": problems,
            "deducted_points": total, "controls": controls, "findings": findings,
            "exceptions": report["exceptions"], "executed": report["executed"], "skipped": report["skipped"],
            "observations": report.get("observations", {}),
            "coverage": dict(Counter(c["status"] for c in controls)),
            "lynis_version": metadata.get("lynis_version"), "hardening_index": metadata.get("hardening_index"),
            "scan_start_local": metadata.get("report_datetime_start"),
            "scan_end_local": metadata.get("report_datetime_end"),
            "scope": "Lynis reported findings only; executed does not prove every subtest passed; scan timestamps use the audited host's unspecified local timezone"}
