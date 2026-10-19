"""Local-only human readable reports, with escaping and no network assets."""
from __future__ import annotations

from collections import Counter
from html import escape
import json
from rogueshield.localio import create_private
from rogueshield.sarif import sarif_report
import unicodedata

RULES: dict[str, tuple[str, str]] = {
    "PY-EVAL": ("Code execution risk", "Remove eval for untrusted expressions; use a strict parser or explicit dispatch."),
    "PY-EXEC": ("Dynamic code execution", "Avoid dynamic exec; use a fixed, auditable action map."),
    "PY-SHELL": ("Shell command execution", "Avoid invoking a shell; use argument arrays and controlled commands."),
    "PY-PICKLE": ("Unsafe data loading", "Avoid deserializing pickle data from untrusted sources."),
    "PY-SHELL-TRUE": ("Shell interpretation enabled", "Use shell=False with a fixed argument list where possible."),
    "API-HTTP": ("Unencrypted API address", "Prefer HTTPS and verify TLS configuration."),
    "API-AUTH-DOC": ("Authorization may be missing", "Document and verify server-side authorization for this API route."),
    "API-OLD-MUTATION": ("Legacy endpoint still modifies data", "Confirm the endpoint is removed or protected with current checks."),
    "INV-CONSERVATION": ("Unexpected balance change", "Verify all authorized mint, burn, fee, debit and credit operations."),
    "INV-NEGATIVE": ("Negative balance", "Make the balance transition atomic and enforce a nonnegative invariant."),
    "INV-REPLAY": ("Operation may repeat its effect", "Require idempotency and atomic claim/settlement operations."),
    "INV-ASSET-CONSERVATION": ("Unexpected asset creation or loss", "Audit each asset independently; verify authorized mint, burn, fees and atomic transfer."),
    "INV-ASSET-NEGATIVE": ("Negative asset balance", "Enforce nonnegative per-asset balances within the same transaction as the transfer."),
}
SEVERITY = ("critical", "high", "medium", "low", "info")


def assemble(mode: str, findings: list[dict], *, checks: int = 1) -> dict:
    if not isinstance(findings, list) or len(findings) > 30_000:
        raise ValueError("Too many findings")
    result = []
    for f in findings:
        rule = str(f.get("rule_id", "UNKNOWN"))[:80]
        severity = str(f.get("severity", "info")).lower()
        if severity not in SEVERITY:
            severity = "info"
        title, action = RULES.get(rule, ("Manual review needed", "Review the finding and validate it before making changes."))
        result.append({"rule_id": rule, "severity": severity, "title": title,
                       "location": str(f.get("location", ""))[:240],
                       "message": str(f.get("message", ""))[:500], "what_to_do": action,
                       "confidence": "review-needed"})
    result.sort(key=lambda x: (SEVERITY.index(x["severity"]), x["rule_id"], x["location"]))
    totals = dict(Counter(x["severity"] for x in result))
    return {"tool": "RogueShield", "schema_version": 1, "mode": mode,
            "status": "review-indicators-found" if result else "no-indicators-in-covered-checks",
            "coverage": {"check_groups_executed": checks,
                         "warning": "These heuristic checks are incomplete; zero findings never proves a system secure."},
            "summary": {"total": len(result), "by_severity": {key: totals.get(key, 0) for key in SEVERITY}},
            "findings": result}


def _terminal_safe(value: object) -> str:
    # Escape terminal control and Unicode formatting characters embedded in
    # attacker-controlled route names and file names, without hiding findings.
    raw = str(value)
    return "".join(c if unicodedata.category(c) not in {"Cc", "Cf", "Cs"}
                   else f"\\u{ord(c):04x}" for c in raw)


def text_report(report: dict) -> str:
    summary = report["summary"]
    lines = ["ROGUESHIELD • SECURITY REVIEW", "=" * 33,
             f"Mode: {_terminal_safe(report['mode'])}", f"Review indicators: {summary['total']}",
             "This is not a security certification or proof of exploitability.", ""]
    if not report["findings"]:
        lines.append("No indicators found in the checks that ran. Additional review may be necessary.")
    for i, f in enumerate(report["findings"], 1):
        lines += [f"{i}. [{f['severity'].upper()}] {_terminal_safe(f['title'])}",
                  f"   Where: {_terminal_safe(f['location'])}", f"   Finding: {_terminal_safe(f['message'])}",
                  f"   Suggested action: {_terminal_safe(f['what_to_do'])}", ""]
    return "\n".join(lines) + "\n"


def html_report(report: dict) -> str:
    def h(s: object) -> str:
        return escape(str(s), quote=True)
    cards = []
    for f in report["findings"]:
        cards.append("<section class='finding'><h3>" + h(f["title"]) + "</h3>"
                     + "<p><strong>Severity:</strong> " + h(f["severity"]) + "</p>"
                     + "<p><strong>Location:</strong> " + h(f["location"]) + "</p>"
                     + "<p><strong>What we noticed:</strong> " + h(f["message"]) + "</p>"
                     + "<p><strong>Suggested next step:</strong> " + h(f["what_to_do"]) + "</p></section>")
    if not cards:
        cards.append("<p>No indicators were found within the checks performed. This is not a security guarantee.</p>")
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            "<title>RogueShield review</title><style>body{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#172533}"
            "header{border-bottom:3px solid #1f6374;padding-bottom:1rem}.finding{border:1px solid #bbc7cd;border-radius:10px;padding:1rem;margin:1rem 0}"
            ".notice{border-left:4px solid #b67d17;padding:.8rem;background:#fffaf0}h1{color:#17465b}</style>"
            "<header><h1>RogueShield security review</h1><p>Mode: " + h(report["mode"]) + "</p><p>Review indicators: "
            + h(report["summary"]["total"]) + "</p></header>"
            "<p class='notice'>Automated review does not guarantee security or demonstrate exploitability.</p>"
            + "".join(cards) + "</html>\n")


def write_report(report: dict, path: str, fmt: str) -> None:
    if fmt not in ("json", "text", "html", "sarif"):
        raise ValueError("Unknown report format")
    if fmt in ("json", "sarif"):
        document = sarif_report(report) if fmt == "sarif" else report
        payload = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    else:
        payload = html_report(report) if fmt == "html" else text_report(report)
    create_private(path, payload)
