"""Local auditor for KV mirror bursts and repeated proof links."""

import re
import json
import hashlib
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s,;\"'<>\]\)]+ ".replace(" ", ""))
DID_RE = re.compile(r"did:key:[A-Za-z0-9]+")
SEQ_RE = re.compile(r"seq\s*[:=]?\s*#?\s*(\d+)", re.IGNORECASE)
LOCALE_RE = re.compile(r"/(en|en-us|en-gb|es|fr|de|ja|zh-cn|zh-tw|pt|pt-br)/?$", re.IGNORECASE)
SLUG_NUM_RE = re.compile(r"^(.*)-(\d+)$")
DID_BODY_RE = re.compile(r"^[A-Za-z0-9]+$")


def clean_tail(url):
    return url.strip().rstrip(".,;!?)'\"")


def normalize_url(url):
    s = clean_tail(url.strip())
    if "://" not in s:
        return s
    try:
        parts = urlsplit(s)
    except ValueError:
        return s
    scheme = parts.scheme.lower() if parts.scheme else "https"
    netloc = parts.netloc.lower()
    if not netloc:
        return s
    path = parts.path or ""
    if path == "/":
        path = ""
    elif len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    m = LOCALE_RE.search(path)
    if m:
        path = path[:m.start()]
        if path == "":
            path = ""
    out = scheme + "://" + netloc + path
    return out


def host_of(normalized_url):
    try:
        p = urlsplit(normalized_url)
        return p.netloc.lower()
    except ValueError:
        return ""


def slug_of(normalized_url):
    try:
        p = urlsplit(normalized_url)
        path = p.path
    except ValueError:
        return ""
    if not path or path == "/":
        return ""
    bits = path.rsplit("/", 1)
    last = bits[-1] if bits else ""
    return last.strip()


def slug_stem(normalized_url):
    slug = slug_of(normalized_url)
    low = slug.lower()
    m = SLUG_NUM_RE.match(low)
    if m:
        stem = m.group(1)
        num = int(m.group(2))
        return (stem, num)
    return (low, None)


def is_did_key_format(did):
    if not did.startswith("did:key:"):
        return False
    body = did[len("did:key:"):]
    if len(body) < 10:
        return False
    if len(body) > 200:
        return False
    if DID_BODY_RE.match(body) is None:
        return False
    return True


def explain_did(did):
    if not did.startswith("did:key:"):
        return {"did": did, "ok": False, "reason": "missing did:key: prefix"}
    body = did[len("did:key:"):]
    if len(body) < 10:
        return {"did": did, "ok": False, "reason": "body too short"}
    if len(body) > 200:
        return {"did": did, "ok": False, "reason": "body too long"}
    if DID_BODY_RE.match(body) is None:
        return {"did": did, "ok": False, "reason": "body has invalid chars"}
    return {"did": did, "ok": True, "reason": "format looks ok"}


def parse_room_export(text):
    entries = []
    lines = text.splitlines()
    for idx, raw in enumerate(lines):
        line = raw.strip()
        if not line:
            continue
        seq = None
        sm = SEQ_RE.search(line)
        if sm:
            try:
                seq = int(sm.group(1))
            except ValueError:
                seq = None
        dids = DID_RE.findall(line)
        raw_urls = URL_RE.findall(line)
        urls = []
        for u in raw_urls:
            urls.append(clean_tail(u))
        kv_urls = []
        x_urls = []
        other_urls = []
        for u in urls:
            low = u.lower()
            if "x.com" in low or "twitter.com" in low:
                x_urls.append(u)
            elif "flop-guide" in low or "/kv" in low or "mirror" in low or "/note" in low or "kv" in low:
                kv_urls.append(u)
            else:
                other_urls.append(u)
        if seq is None and not dids and not urls:
            continue
        entries.append({
            "line": idx + 1,
            "seq": seq,
            "dids": dids,
            "kv_urls": kv_urls,
            "x_urls": x_urls,
            "other_urls": other_urls,
            "text": line[:300],
        })
    return entries


def collect_artifacts(entries):
    arts = []
    for e in entries:
        seq = e.get("seq")
        dids = e.get("dids") or []
        did = dids[0] if dids else ""
        line = e.get("line", 0)
        pairs = []
        for u in e.get("kv_urls", []):
            pairs.append((u, "kv_mirror"))
        for u in e.get("x_urls", []):
            pairs.append((u, "x_proof"))
        for u in e.get("other_urls", []):
            pairs.append((u, "other"))
        for raw_url, kind in pairs:
            norm = normalize_url(raw_url)
            stem, num = slug_stem(norm)
            arts.append({
                "kind": kind,
                "raw_url": raw_url,
                "normalized_url": norm,
                "stem": stem,
                "number": num,
                "seq": seq,
                "did": did,
                "line": line,
            })
    return arts


def group_by_normalized(artifacts):
    groups = {}
    for a in artifacts:
        key = a.get("normalized_url", "")
        groups.setdefault(key, []).append(a)
    return groups


def group_by_stem(artifacts):
    groups = {}
    for a in artifacts:
        norm = a.get("normalized_url", "")
        host = host_of(norm)
        stem = a.get("stem", "")
        if not stem:
            stem = "(root)"
        if host:
            key = host + "/" + stem
        else:
            key = stem
        groups.setdefault(key, []).append(a)
    return groups


def check_limits(artifacts, limit=2, seq_window=500):
    findings = []
    exact = group_by_normalized(artifacts)
    for key in sorted(exact.keys()):
        items = exact[key]
        if not key:
            continue
        seqs = sorted([x.get("seq") for x in items if x.get("seq") is not None])
        count = len(items)
        if seqs:
            smin = seqs[0]
            smax = seqs[-1]
            span = smax - smin
        else:
            smin = None
            smax = None
            span = None
        dids = sorted(set([x.get("did", "") for x in items if x.get("did")]))
        kind = items[0].get("kind", "") if items else ""
        exceeded = False
        if count > limit:
            if span is None:
                exceeded = True
            elif span <= seq_window:
                exceeded = True
        findings.append({
            "rule": "exact",
            "key": key,
            "canonical_url": key,
            "kind": kind,
            "count": count,
            "seq_min": smin,
            "seq_max": smax,
            "seq_span": span,
            "canonical_seq": smin,
            "dids": dids,
            "exceeded": exceeded,
        })
    stems = group_by_stem(artifacts)
    for key in sorted(stems.keys()):
        items = stems[key]
        distinct = sorted(set([x.get("normalized_url", "") for x in items]))
        count = len(items)
        if len(distinct) <= 1 and count <= limit:
            continue
        seqs = sorted([x.get("seq") for x in items if x.get("seq") is not None])
        if seqs:
            smin = seqs[0]
            smax = seqs[-1]
            span = smax - smin
        else:
            smin = None
            smax = None
            span = None
        dids = sorted(set([x.get("did", "") for x in items if x.get("did")]))
        canon = ""
        canon_seq = smin
        if seqs:
            found = None
            for x in items:
                if x.get("seq") == smin:
                    found = x
                    break
            if found is not None:
                canon = found.get("normalized_url", "")
            elif distinct:
                canon = distinct[0]
        elif distinct:
            canon = distinct[0]
        exceeded = False
        if count > limit or len(distinct) > limit:
            if span is None:
                exceeded = True
            elif span <= seq_window:
                exceeded = True
        if len(distinct) > 1 or exceeded:
            findings.append({
                "rule": "stem",
                "key": key,
                "canonical_url": canon,
                "kind": "mixed",
                "count": count,
                "distinct_urls": len(distinct),
                "urls": distinct[:20],
                "seq_min": smin,
                "seq_max": smax,
                "seq_span": span,
                "canonical_seq": canon_seq,
                "dids": dids,
                "exceeded": exceeded,
            })
    return findings


def seq_gaps(artifacts):
    with_seq = [a for a in artifacts if a.get("seq") is not None]
    ordered = sorted(with_seq, key=lambda x: x.get("seq"))
    out = []
    prev = None
    for a in ordered:
        cur = a.get("seq")
        if prev is None:
            gap = 0
        else:
            gap = cur - prev
        out.append({
            "seq": cur,
            "gap": gap,
            "normalized_url": a.get("normalized_url", ""),
            "kind": a.get("kind", ""),
            "did": a.get("did", ""),
            "line": a.get("line", 0),
        })
        prev = cur
    return out


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_report(entries, artifacts, findings, gaps, limit=2, seq_window=500):
    urls = sorted(set([a.get("normalized_url", "") for a in artifacts if a.get("normalized_url")]))
    seen_dids = []
    for e in entries:
        for d in e.get("dids", []):
            if d not in seen_dids:
                seen_dids.append(d)
    for a in artifacts:
        d = a.get("did", "")
        if d and d not in seen_dids:
            seen_dids.append(d)
    seen_dids = sorted(seen_dids)
    url_checks = []
    for u in urls:
        url_checks.append({"url": u, "sha256": sha256_hex(u)})
    did_checks = []
    for d in seen_dids:
        if not d:
            continue
        info = explain_did(d)
        info["sha256"] = sha256_hex(d)
        did_checks.append(info)
    exceeded = [f for f in findings if f.get("exceeded")]
    kv_n = len([a for a in artifacts if a.get("kind") == "kv_mirror"])
    xp_n = len([a for a in artifacts if a.get("kind") == "x_proof"])
    report = {
        "summary": {
            "lines_parsed": len(entries),
            "artifacts": len(artifacts),
            "kv_mirrors": kv_n,
            "x_proofs": xp_n,
            "findings": len(findings),
            "exceeded": len(exceeded),
            "limit": limit,
            "seq_window": seq_window,
        },
        "findings": findings,
        "gaps": gaps,
        "url_checksums": url_checks,
        "did_checks": did_checks,
    }
    return report


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=True)


def render_markdown(report):
    lines = []
    lines.append("# KV Mirror Replica-Limit Audit")
    lines.append("")
    s = report.get("summary", {})
    lines.append("Summary: lines=" + str(s.get("lines_parsed", 0)) + " artifacts=" + str(s.get("artifacts", 0)) + " kv=" + str(s.get("kv_mirrors", 0)) + " proofs=" + str(s.get("x_proofs", 0)))
    lines.append("Limit: " + str(s.get("limit", 0)) + " window: " + str(s.get("seq_window", 0)) + " exceeded: " + str(s.get("exceeded", 0)))
    lines.append("")
    lines.append("## Findings")
    findings = report.get("findings", [])
    if not findings:
        lines.append("No artifacts found.")
    else:
        for f in findings:
            if f.get("exceeded"):
                status = "EXCEEDED"
            else:
                status = "ok"
            key = f.get("key", "")
            canon = f.get("canonical_url", "")
            cseq = f.get("canonical_seq")
            lines.append("- [" + status + "] " + str(f.get("rule", "")) + " " + key + " count=" + str(f.get("count", 0)) + " span=" + str(f.get("seq_span")) + " canonical=" + str(canon) + " seq=" + str(cseq))
    lines.append("")
    lines.append("## Seq gaps")
    gaps = report.get("gaps", [])
    if not gaps:
        lines.append("No seq ordered artifacts.")
    else:
        for g in gaps[:50]:
            lines.append("- seq " + str(g.get("seq")) + " gap " + str(g.get("gap")) + " " + str(g.get("normalized_url", "")))
    lines.append("")
    lines.append("## URL checksums")
    for u in report.get("url_checksums", [])[:50]:
        lines.append("- " + str(u.get("url", "")) + " sha256:" + str(u.get("sha256", "")))
    lines.append("")
    lines.append("## DID checks")
    for d in report.get("did_checks", [])[:50]:
        lines.append("- " + str(d.get("did", "")) + " ok=" + str(d.get("ok")) + " sha256:" + str(d.get("sha256", "")))
    lines.append("")
    lines.append("Note: read-only review. Flagged variants may be intentional; keep human review.")
    return "\n".join(lines) + "\n"
