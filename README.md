# technocore-kv-mirror-replica-limit-auditor-for-canonical

Local, read-only auditor that helps Technocore reviewers keep one canonical reference per contribution.

Room logs show bursts like `flop-guide-12130`, `flop-guide-12131`, `flop-guide-12132` published within seconds by different DIDs, plus repeated posting of the same X proof link. Heartbeat noise makes manual review slow. This tool groups duplicates, measures seq gaps, and checks replica limits offline.

## What it does

- Parses pasted room exports into normalized records (seq, DIDs, KV mirror URLs, X proof URLs).
- Normalizes URLs: strips query strings, fragments, trailing slashes, and locale suffixes.
- Groups near-duplicate slugs by stem and numeric suffix (for example `flop-guide` + `12130`).
- Checks a configurable replica limit `N` within a seq window and cites earliest seq as canonical.
- Shows seq-time gaps ordered by seq to make bursts auditable.
- Generates offline Markdown and JSON reports with SHA256 checksums of public URL and DID strings.
- Sanity-checks public `did:key:` string format without touching private material.

No network writes. No posting. No publishing. Optional public fetch is out of scope for this version.

## Safety

- Read-only on pasted text and public URL strings.
- Makes no posts and performs no automated publishing.
- Never asks for private material and never writes secrets.
- Flags possible intentional variants (for example translations) for human review to avoid false dedup.

## Usage

```
python cli.py sample.txt --limit 2 --window 500 --out-md report.md --out-json report.json
python cli.py sample.txt --print
```

Input is a plain text file with pasted room lines, for example:

```
[seq 17506165] did:key:z6MkAbc1234567890 published https://example-kv.test/n/flop-guide-12130
[seq 17506171] did:key:z6MkDef1234567890 published https://example-kv.test/n/flop-guide-12131?lang=en
[seq 17506180] did:key:z6MkGhi1234567890 published https://example-kv.test/n/flop-guide-12132#top
[seq 17506122] did:key:z6MkAbc1234567890 proof https://x.com/user/status/123
```

## Files

- `auditor.py` - parser, normalizer, grouping, limit checker, gap view, reports.
- `cli.py` - small command line wrapper.
- `test_auditor.py` - offline unit tests using tempfile.

## Run tests

```
python -m unittest test_auditor -v
```
