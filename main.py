#!/usr/bin/env python3
# security-posture-scorer — AI security posture scorer that scans a codebase or config for misconfigurations, missing security headers, weak crypto, and dependency risks, then produces a 0-100 score with LLM-justified deductions and a prioritized fix list.
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_client import LLM
def score(args):
    """Score a codebase or config for security posture."""
    llm = LLM()
    target = args.path if args.path else (args.config if args.config else ".")
    print(f"Scanning security posture: {target}")
    findings = prescan(target)
    print(f"Pre-scan found {len(findings)} static issues")
    report = llm.generate(
        f"Tech stack: {args.stack}\n\nStatic findings:\n{json.dumps(findings, indent=2)}\n\n"
        "Score this security posture from 0-100. For each point deducted, write the exact reason. "
        "Then produce a prioritized fix list ranked by (risk reduction / effort). "
        "Respond as JSON: {"score": 82, "deductions": [{"points": 5, "finding": "...", "why": "..."}], "fixes": [{"priority": 1, "action": "...", "effort": "low|medium|high", "impact": "..."}], "summary": "..."}",
        system="You are a senior application security engineer. Be strict but fair — 100 is perfect, 0 is an open port with default credentials."
    )
    parsed = _json(report)
    s = parsed.get("score", 0)
    print(f"\n{'='*60}\nSECURITY POSTURE SCORE: {s}/100\n{'='*60}")
    print(f"Summary: {parsed.get('summary', '')}")
    print(f"\nDeductions:")
    for d in parsed.get("deductions", []):
        print(f"  -{d.get('points', 0):>2}  {d.get('finding', '')}\n      why: {d.get('why', '')}")
    print(f"\nPrioritized fixes:")
    for i, f in enumerate(parsed.get("fixes", [])[:8], 1):
        print(f"  {i}. [{f.get('effort', '?')}] {f.get('action', '')} — impact: {f.get('impact', '')}")
    out = {"target": str(target), "score": s, "findings": findings, **parsed}
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(_render_md(out))
        print(f"\nReport written to {args.output}")
    return out

def diff(args):
    """Compare two posture scores."""
    llm = LLM()
    before = json.load(open(args.before))
    after = json.load(open(args.after))
    delta = after.get("score", 0) - before.get("score", 0)
    print(f"Before: {before.get('score', 0)}/100   After: {after.get('score', 0)}/100   Delta: {delta:+d}")
    narrative = llm.generate(
        f"Before score: {json.dumps({k: before.get(k) for k in ('score', 'summary')})}\nAfter score: {json.dumps({k: after.get(k) for k in ('score', 'summary')})}\n\nWrite a short posture trend analysis: what improved, what regressed, what's still the biggest risk.",
        system="You are a CISO reviewing posture trend for the board."
    )
    print("\n" + narrative)

def headers(args):
    """Audit HTTP security headers from a sample response or config."""
    llm = LLM()
    sample = ""
    if args.file:
        sample = open(args.file).read()
    audit = llm.extract(
        sample or "no sample provided — audit a typical Flask/Express/Node app",
        {"missing_headers": [], "present_headers": [], "weak_values": [], "recommendations": []},
        instructions="Audit HTTP security headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Set-Cookie flags (Secure, HttpOnly, SameSite). List what's missing, what's present, what's weakly configured, and concrete fixes."
    )
    print(json.dumps(audit, indent=2))

def deps(args):
    """Triage dependency risks from a manifest."""
    llm = LLM()
    manifest = ""
    for name in ("requirements.txt", "package.json", "go.mod", "Cargo.toml"):
        p = os.path.join(args.path, name)
        if os.path.exists(p):
            manifest = f"{name}:\n" + open(p).read()
            break
    if not manifest:
        print("No dependency manifest found in " + args.path)
        return
    triage = llm.generate(
        f"Dependency manifest:\n{manifest}\n\nIdentify risky dependencies (known CVEs, unmaintained, typosquat-prone, oversized attack surface). Rank by risk. Respond as JSON: {{"risks": [{{"dep": "...", "risk": "high|medium|low", "why": "...", "fix": "..."}}]}}",
        system="You are a supply-chain security analyst."
    )
    parsed = _json(triage)
    for r in parsed.get("risks", []):
        print(f"  [{r.get('risk', '?').upper():>6}] {r.get('dep', '')}: {r.get('why', '')} -> {r.get('fix', '')}")

def prescan(target):
    """Static scan for common security smells before the LLM runs."""
    import re
    findings = []
    if os.path.isfile(target) and target.endswith((".json", ".yaml", ".yml")):
        text = open(target).read()
        for pat, msg in [
            (r'"?debug"?\s*:\s*true', "debug mode enabled in config"),
            (r'"?allow_origins"?\s*:\s*\[?\s*"\*"', "CORS allow_origins = *"),
            (r'"?ssl"?\s*:\s*false', "TLS disabled in config"),
        ]:
            if re.search(pat, text):
                findings.append({"type": "config", "detail": msg})
        return findings
    if not os.path.isdir(target):
        return findings
    exts = {".py", ".js", ".ts", ".go", ".rb", ".java"}
    secrets = re.compile(r"(api[_-]?key|secret|password|token)\s*[=:]\s*['"][A-Za-z0-9_\-]{8,}")
    weak = re.compile(r"(md5|sha1|DES|ECB)")
    for root, _, files in os.walk(target):
        if any(seg in root for seg in (".git", "node_modules", "venv", "__pycache__")):
            continue
        for fn in files:
            if os.path.splitext(fn)[1] not in exts:
                continue
            p = os.path.join(root, fn)
            try:
                text = open(p, errors="ignore").read()
            except OSError:
                continue
            for m in secrets.finditer(text):
                findings.append({"type": "hardcoded-credential", "file": p, "line": text[:m.start()].count("\n") + 1})
            for m in weak.finditer(text):
                findings.append({"type": "weak-crypto", "file": p, "detail": m.group(0)})
    return findings[:40]

def _json(text):
    start, end = text.find("{"), text.rfind("}") + 1
    if start < 0 or end <= 1:
        return {}
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return {}

def _render_md(r):
    lines = [f"# Security Posture Report", f"", f"**Score: {r.get('score', '?')}/100**", f"", r.get("summary", ""), f"", "## Deductions", ""]
    for d in r.get("deductions", []):
        lines.append(f"- **-{d.get('points', 0)}** {d.get('finding', '')}")
        lines.append(f"  - {d.get('why', '')}")
    lines += ["", "## Prioritized Fixes", ""]
    for i, f in enumerate(r.get("fixes", []), 1):
        lines.append(f"{i}. [{f.get('effort', '?')}] {f.get('action', '')} — {f.get('impact', '')}")
    lines += ["", "## Static Findings", ""]
    for f in r.get("findings", []):
        lines.append(f"- {f.get('type', '?')}: {f.get('detail', '') or f.get('file', '')}")
    return "\n".join(lines) + "\n"

def main():
    import argparse
    p = argparse.ArgumentParser(description="security-posture-scorer")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score", help="score a codebase or config")
    s.add_argument("--path"); s.add_argument("--config"); s.add_argument("--stack", default="python")
    s.add_argument("--output"); s.set_defaults(fn=score)
    d = sub.add_parser("diff", help="compare two scores")
    d.add_argument("--before", required=True); d.add_argument("--after", required=True); d.set_defaults(fn=diff)
    h = sub.add_parser("headers", help="audit security headers")
    h.add_argument("--file"); h.set_defaults(fn=headers)
    e = sub.add_parser("deps", help="triage dependency risks")
    e.add_argument("--path", default="."); e.set_defaults(fn=deps)
    args = p.parse_args()
    args.fn(args)

if __name__ == '__main__':
    main()
