import unittest
import tempfile
import json
import auditor

SAMPLE = """[seq 17506165] did:key:z6MkAbc1234567890 published https://example-kv.test/n/flop-guide-12130
[seq 17506171] did:key:z6MkDef1234567890 published https://example-kv.test/n/flop-guide-12131?lang=en
[seq 17506180] did:key:z6MkGhi1234567890 published https://example-kv.test/n/flop-guide-12132#top
[seq 17506122] did:key:z6MkAbc1234567890 proof https://x.com/user/status/123
[seq 17506154] did:key:z6MkAbc1234567890 proof https://x.com/user/status/123?x=1
"""


class TestAuditor(unittest.TestCase):
    def test_parse_extracts_seq_did_urls(self):
        entries = auditor.parse_room_export(SAMPLE)
        self.assertEqual(len(entries), 5)
        seqs = [e["seq"] for e in entries]
        self.assertIn(17506165, seqs)
        self.assertIn(17506122, seqs)
        first = entries[0]
        self.assertEqual(first["dids"], ["did:key:z6MkAbc1234567890"])
        self.assertEqual(len(first["kv_urls"]), 1)
        proofs = [e for e in entries if e["x_urls"]]
        self.assertEqual(len(proofs), 2)

    def test_normalize_strips_query_fragment_locale(self):
        a = auditor.normalize_url("https://Example-KV.test/n/flop-guide-12131?lang=en#top")
        self.assertEqual(a, "https://example-kv.test/n/flop-guide-12131")
        b = auditor.normalize_url("https://example-kv.test/n/flop-guide-12131/")
        self.assertEqual(b, "https://example-kv.test/n/flop-guide-12131")
        c = auditor.normalize_url("https://example-kv.test/n/flop-guide-12131/en")
        self.assertEqual(c, "https://example-kv.test/n/flop-guide-12131")

    def test_slug_stem_groups_burst(self):
        s1, n1 = auditor.slug_stem("https://example-kv.test/n/flop-guide-12130")
        s2, n2 = auditor.slug_stem("https://example-kv.test/n/flop-guide-12131")
        self.assertEqual(s1, "flop-guide")
        self.assertEqual(s1, s2)
        self.assertEqual(n1, 12130)
        self.assertEqual(n2, 12131)
        entries = auditor.parse_room_export(SAMPLE)
        arts = auditor.collect_artifacts(entries)
        groups = auditor.group_by_stem(arts)
        found = False
        for key, items in groups.items():
            if "flop-guide" in key:
                found = True
                self.assertEqual(len(items), 3)
        self.assertTrue(found)

    def test_replica_limit_flags_and_canonical(self):
        entries = auditor.parse_room_export(SAMPLE)
        arts = auditor.collect_artifacts(entries)
        findings = auditor.check_limits(arts, limit=1, seq_window=500)
        exact_hit = [f for f in findings if f["rule"] == "exact" and f["exceeded"]]
        self.assertTrue(len(exact_hit) >= 1)
        stem_hit = [f for f in findings if f["rule"] == "stem" and f["exceeded"]]
        self.assertTrue(len(stem_hit) >= 1)
        stem = stem_hit[0]
        self.assertEqual(stem["canonical_seq"], 17506165)
        self.assertIn("flop-guide-12130", stem["canonical_url"])

    def test_seq_gaps_ordered(self):
        entries = auditor.parse_room_export(SAMPLE)
        arts = auditor.collect_artifacts(entries)
        gaps = auditor.seq_gaps(arts)
        self.assertEqual(len(gaps), 5)
        seqs = [g["seq"] for g in gaps]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(gaps[0]["gap"], 0)
        self.assertEqual(gaps[1]["gap"], gaps[1]["seq"] - gaps[0]["seq"])

    def test_did_format(self):
        self.assertTrue(auditor.is_did_key_format("did:key:z6MkAbc1234567890"))
        self.assertFalse(auditor.is_did_key_format("did:web:example"))
        self.assertFalse(auditor.is_did_key_format("did:key:short"))
        info = auditor.explain_did("did:key:z6MkAbc1234567890")
        self.assertTrue(info["ok"])

    def test_report_and_checksums_with_tempfile(self):
        entries = auditor.parse_room_export(SAMPLE)
        arts = auditor.collect_artifacts(entries)
        findings = auditor.check_limits(arts, limit=2, seq_window=500)
        gaps = auditor.seq_gaps(arts)
        report = auditor.build_report(entries, arts, findings, gaps, limit=2, seq_window=500)
        md = auditor.render_markdown(report)
        js = auditor.render_json(report)
        self.assertIn("KV Mirror", md)
        self.assertIn("Seq gaps", md)
        data = json.loads(js)
        self.assertIn("summary", data)
        self.assertIn("url_checksums", data)
        with tempfile.TemporaryDirectory() as tmp:
            p1 = tmp + "/report.json"
            p2 = tmp + "/report.md"
            with open(p1, "w", encoding="utf-8") as f:
                f.write(js)
            with open(p2, "w", encoding="utf-8") as f:
                f.write(md)
            with open(p1, "r", encoding="utf-8") as f:
                back = json.load(f)
            self.assertEqual(back["summary"]["artifacts"], 5)
            with open(p2, "r", encoding="utf-8") as f:
                text = f.read()
            self.assertIn("canonical", text.lower())

    def test_empty_input(self):
        entries = auditor.parse_room_export("")
        self.assertEqual(entries, [])
        arts = auditor.collect_artifacts(entries)
        self.assertEqual(arts, [])
        gaps = auditor.seq_gaps(arts)
        self.assertEqual(gaps, [])


if __name__ == "__main__":
    unittest.main()
