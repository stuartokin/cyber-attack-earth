#!/usr/bin/env python3
"""Unit checks for build_cyber_data.py. No network: every fetch is faked.

Each test pins a bug that was fixed, so it stays fixed. Run from tests/:
    python3 test_builder.py
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("builder", ROOT / "build_cyber_data.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class FakeResp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text
        self.content = text.encode()

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)


class Unlist(unittest.TestCase):
    def test_python_list_text(self):
        self.assertEqual(B._unlist("['Health', 'Finance']"), "Health;Finance")
        self.assertEqual(B._unlist("['State institutions / political system']"),
                         "State institutions / political system")

    def test_leaves_plain_and_broken_alone(self):
        self.assertEqual(B._unlist("Health"), "Health")
        self.assertEqual(B._unlist("[broken"), "[broken")


class EuRepoC(unittest.TestCase):
    CSV = ("incident_id,name,start_date,receiver_country,receiver_category,"
           "receiver_subcategory,initiator_country,weighted_intensity,"
           "economic_impact_value,Data theft,Disruption,Ransomware\n"
           "1,Test op,2017-06-27,Ukraine,\"['Critical infrastructure']\","
           "\"['Energy', 'Finance']\",Russia,5,20,0,1,1\n")

    def test_type_sector_and_intensity(self):
        with mock.patch.object(B, "eurepoc_release_csv", return_value=self.CSV):
            rows = B.build_eurepoc()
        r = rows[0]
        self.assertEqual(r["incident_type"], "Disruption;Ransomware")
        self.assertEqual(r["receiver_subcategory"], "Energy;Finance")
        self.assertEqual(r["receiver_category"], "Critical infrastructure")
        self.assertEqual(r["imp"]["intensity"], 5)
        # value with no stated unit must NOT become a dollar figure
        self.assertNotIn("financial", r["imp"])


class ShrinkGuard(unittest.TestCase):
    def src(self, ratio=0.9):
        return B.Source(id="x", table="t", title="X", licence="", homepage="", keep_ratio=ratio)

    def test_holds_a_big_drop(self):
        why = B.shrink_check(self.src(), 500, {"status": "ok", "rows": 1000})
        self.assertIn("shrank from 1000 to 500", why)

    def test_accepts_growth_small_wobble_and_override(self):
        self.assertEqual(B.shrink_check(self.src(), 1100, {"status": "ok", "rows": 1000}), "")
        self.assertEqual(B.shrink_check(self.src(), 95, {"status": "ok", "rows": 110}), "")
        self.assertEqual(B.shrink_check(self.src(), 10, {"status": "ok", "rows": 1000}, {"x"}), "")
        self.assertEqual(B.shrink_check(self.src(), 10, None), "")


class CarryForward(unittest.TestCase):
    def test_failed_and_unscheduled_sources_stay_listed(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "incidents").mkdir()
            (d / "incidents" / "rwlive.json").write_text("{}")
            (d / "vulns").mkdir()
            (d / "vulns" / "kev.json").write_text("[]")
            prev = {"incidents": {"files": {"rwlive": "incidents/rwlive.json",
                                            "eurepoc": "incidents/eurepoc.json"},
                                  "counts": {"rwlive": 900, "eurepoc": 50}, "total": 950},
                    "vulns": {"files": {"kev": {"file": "vulns/kev.json", "rows": 3}}}}
            tables = {"incidents": {"files": {"eurepoc": "incidents/eurepoc.json"},
                                    "counts": {"eurepoc": 60}, "total": 60}}
            B.carry_forward(tables, prev, {"eurepoc"}, d)
            self.assertEqual(tables["incidents"]["files"]["rwlive"], "incidents/rwlive.json")
            self.assertEqual(tables["incidents"]["counts"], {"eurepoc": 60, "rwlive": 900})
            self.assertEqual(tables["incidents"]["total"], 960)
            self.assertEqual(tables["vulns"]["files"]["kev"]["rows"], 3)
        finally:
            shutil.rmtree(d)

    def test_missing_file_is_not_carried(self):
        d = Path(tempfile.mkdtemp())
        try:
            prev = {"vulns": {"files": {"kev": {"file": "vulns/kev.json", "rows": 3}}}}
            tables = {}
            B.carry_forward(tables, prev, set(), d)
            self.assertNotIn("vulns", tables)
        finally:
            shutil.rmtree(d)


class MainKeepsFailedSource(unittest.TestCase):
    """End to end: a source that raises keeps its previous files in the manifest."""

    def test_main(self):
        d = Path(tempfile.mkdtemp())
        reg = list(B.REGISTRY)
        try:
            (d / "reports").mkdir(parents=True)
            (d / "reports" / "vendor.json").write_text('[{"org":"A"}]')
            (d / "manifest.json").write_text(json.dumps({
                "generated": "2026-11-01T00:00:00+00:00",
                "tables": {"reports": {"files": {"vendor": {"file": "reports/vendor.json", "rows": 1}}}},
                "sources": [{"id": "reports", "status": "ok", "rows": 1,
                             "refreshed": "2026-11-01T00:00:00+00:00"}]}))

            def boom():
                raise RuntimeError("upstream down")
            B.REGISTRY[:] = [B.Source(id="reports", table="reports", title="R",
                                      licence="", homepage="", fn=boom)]
            with mock.patch.object(sys, "argv", ["x", str(d)]), \
                    mock.patch.dict(os.environ, {"GITHUB_TOKEN": "", "ONLY_SOURCES": "", "GITHUB_ACTIONS": ""}):
                B.main()
            m = json.loads((d / "manifest.json").read_text())
            self.assertEqual(m["tables"]["reports"]["files"]["vendor"]["file"], "reports/vendor.json")
            e = m["sources"][0]
            self.assertTrue(e["status"].startswith("failed"))
            self.assertEqual(e["rows"], 1)
            self.assertTrue(e["carried"])
            self.assertEqual(e["refreshed"], "2026-11-01T00:00:00+00:00")
        finally:
            B.REGISTRY[:] = reg
            B.PROBLEMS.clear()
            shutil.rmtree(d)


class RansomwareLive(unittest.TestCase):
    def test_incremental_merges_current_month_and_caps_429(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "incidents").mkdir()
            (d / "incidents" / "rwlive.json").write_text(json.dumps(
                {"2021-01": [{"victim": "old", "group": "g", "attackdate": "2021-01-02",
                              "discovered": "2021-01-02", "country": "GB",
                              "activity": "", "press": 0}]}))
            calls = []

            def fake_get(url, **kw):
                calls.append(url)
                if len(calls) <= 4:          # first month: always "slow down"
                    return FakeResp(429)
                return FakeResp(200, [{"victim": "b", "group": "z", "country": "us",
                                       "discovered": "2026-01-05"},
                                      {"victim": "a", "group": "z", "country": "fr",
                                       "discovered": "2026-01-04"}])
            with mock.patch.object(B.requests, "get", side_effect=fake_get), \
                    mock.patch.object(B.time, "sleep"), \
                    mock.patch.dict(os.environ, {"RWLIVE_FULL": ""}):
                out = B.build_rwlive(out_dir=d)
            today = B.date.today()
            cur = "/%d/%02d" % (today.year, today.month)
            self.assertIn(cur, calls[0])                       # current month is fetched
            self.assertEqual(len(calls), 4 + B.RWLIVE_RECENT_MONTHS)   # 4 tries, then move on
            self.assertIn("2021-01", out)                      # history kept
            some = next(v for k, v in out.items() if k != "2021-01" and v)
            self.assertEqual([r["victim"] for r in some], ["a", "b"])  # sorted
        finally:
            shutil.rmtree(d)


class ManualFiles(unittest.TestCase):
    def test_cissm_never_reads_estimates_or_review(self):
        d = Path(tempfile.mkdtemp())
        cwd = os.getcwd()
        try:
            os.chdir(d)
            Path("manual_sources").mkdir()
            Path("estimates.csv").write_text("id,value\n1,2\n")
            Path("manual_sources/sec_review.csv").write_text("cik,filed\n1,2\n")
            self.assertIsNone(B._manual_rows("cissm", allow_any=True))
            Path("cyber_events_2026-11-01.csv").write_text("event_date,country\n2026-01-01,GB\n")
            rows = B._manual_rows("cissm", allow_any=True)
            self.assertEqual(rows[0]["country"], "GB")
            self.assertEqual(B.MANUAL_EXPORTS["cissm"]["dated"], "2026-11-01")
        finally:
            os.chdir(cwd)
            shutil.rmtree(d)


class CissmByApi(unittest.TestCase):
    def test_api_fetch_stops_export_age_reminders(self):
        B.MANUAL_EXPORTS.clear(); B.REMOTE_OK.clear()
        with mock.patch.object(B, "_cissm_fetch_remote",
                               return_value=[{"event_date": "2026-01-01", "country": "GB"}]):
            try:
                B.build_cissm()
            except Exception:
                pass                    # row mapping is not under test here
        self.assertIn("cissm", B.REMOTE_OK)
        B.carry_manual_exports({"manual_exports": {"cissm": {"dated": "2026-07-24", "age_days": 1}}})
        self.assertNotIn("cissm", B.MANUAL_EXPORTS)
        B.REMOTE_OK.clear()


class CissmPaging(unittest.TestCase):
    def test_sorted_pages_and_repeats_dropped(self):
        pages = [[{"id": "a"}, {"id": "b"}], [{"id": "b"}, {"id": "c"}], [{"id": "d"}]]
        seen = []

        def fake(url, key, params=None):
            seen.append(dict(params or {}))
            return FakeResp(200, pages[len(seen) - 1])
        with mock.patch.object(B, "_cissm_get", side_effect=fake), \
                mock.patch.object(B, "CISSM_PAGE_SIZE", 2), mock.patch.object(B.time, "sleep"):
            rows = B._cissm_pull_entity("u", "k")
        self.assertEqual([r["id"] for r in rows], ["a", "b", "c", "d"])
        self.assertEqual(seen[0]["sort"], "-event_date")


class AttackCampaigns(unittest.TestCase):
    def test_campaigns_with_attribution_and_clean_text(self):
        bundle = {"objects": [
            {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT Test"},
            {"type": "campaign", "id": "campaign--1", "name": "Op Test",
             "first_seen": "2009-11-01T00:00:00Z", "last_seen": "2011-02-01T00:00:00Z",
             "description": "[Op Test](https://attack.mitre.org/campaigns/C0001) targeted energy firms. More.(Citation: X)",
             "external_references": [{"source_name": "mitre-attack", "external_id": "C0001",
                                      "url": "https://attack.mitre.org/campaigns/C0001"}]},
            {"type": "campaign", "id": "campaign--2", "name": "Gone", "revoked": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "C0002"}]},
            {"type": "relationship", "relationship_type": "attributed-to",
             "source_ref": "campaign--1", "target_ref": "intrusion-set--1"}]}
        c = B._attack_campaigns(bundle)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0]["first_seen"], "2009-11")
        self.assertEqual(c[0]["groups"], ["APT Test"])
        self.assertEqual(c[0]["desc"], "Op Test targeted energy firms.")


class ChangeSinceLastRun(unittest.TestCase):
    def test_manifest_records_change(self):
        d = Path(tempfile.mkdtemp())
        reg = list(B.REGISTRY)
        try:
            (d / "manifest.json").write_text(json.dumps({"tables": {}, "sources": [
                {"id": "reports", "status": "ok", "rows": 10, "refreshed": "2026-11-01T00:00:00+00:00"}]}))
            B.REGISTRY[:] = [B.Source(id="reports", table="reports", title="R", licence="",
                                      homepage="", fn=lambda: [{"org": "A"}] * 12)]
            with mock.patch.object(sys, "argv", ["x", str(d)]), \
                    mock.patch.dict(os.environ, {"GITHUB_TOKEN": "", "ONLY_SOURCES": "", "GITHUB_ACTIONS": ""}):
                B.main()
            e = json.loads((d / "manifest.json").read_text())["sources"][0]
            self.assertEqual(e["change"], 2)
            self.assertTrue(e["changed_at"])
        finally:
            B.REGISTRY[:] = reg
            B.PROBLEMS.clear()
            shutil.rmtree(d)


class SecLinks(unittest.TestCase):
    def test_dashed_accession(self):
        self.assertEqual(B._dashed("000121390026119240"), "0001213900-26-119240")


if __name__ == "__main__":
    unittest.main(verbosity=1)
