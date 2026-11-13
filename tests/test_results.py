# -*- coding: utf-8 -*-
"""Результаты в results/ согласованы между собой, с протоколом и со сводкой results/summary.md."""
import hashlib
import json
import os
import subprocess
import sys

from adv import report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")


def _load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


def test_analysis_bound_to_protocol():
    with open(os.path.join(ROOT, "docs", "PROTOCOL.md"), "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    assert _load("analysis.json")["protocol_sha256"] == digest
    assert _load("analysis.json")["scii_gate"]["commit"] == "d210811f27a9b9302f018faf7f019d38dfbb9227"


def test_hypotheses_verdicts():
    an, mono, emu, mut = _load("analysis.json"), _load("monotonicity.json"), _load("emulation.json"), _load("mutation.json")
    hs = {h["id"]: h for h in report.hypotheses(an, mono, emu["pmi"], emu["goals"], mut)}
    for code in ("Г0", "Г1", "Г2", "Г3", "Г4", "Г5", "Г6", "Г7", "Г8", "разд. 3.4"):
        assert hs[code]["ok"] is True, (code, hs[code]["text"])
    assert hs["В5"]["ok"] is None


def test_emulation_has_no_mismatches():
    emu = _load("emulation.json")
    assert emu["goals"]["mismatches"] == []
    assert emu["goals"]["best"]["bundles"] == sum(len(v) for d in _load("analysis.json")["attack_records"].values()
                                                  for v in d.values())


def test_key_numbers():
    """Числа, на которые опирается текст статьи (вариант D1, участники по отдельности)."""
    fam = _load("analysis.json")["deployments"]["D1"]["separate"]["families"]
    k = {r: [fam[g][r]["admit"]["k"] for g in ("Ц1", "Ц2", "Ц3", "Ц4", "Ц5", "Ц6")] for r in ("П1", "П3", "П5", "П10")}
    assert k == {"П1": [1, 1, 1, 1, 3, 1], "П3": [1, 2, 1, 2, 4, None], "П5": [2, 3, 2, 3, 3, 2],
                 "П10": [2, 3, 3, 3, 6, None]}
    av = _load("analysis.json")["availability"]["D1"]["incomplete"]
    assert (av["П10"]["отказ"], av["П7"]["отказ"]) == (561, 4095)


def test_summary_is_up_to_date(tmp_path):
    with open(os.path.join(RES, "summary.md"), encoding="utf-8") as f:
        before = f.read()
    subprocess.run([sys.executable, "-m", "adv.report"], cwd=ROOT, check=True, capture_output=True)
    with open(os.path.join(RES, "summary.md"), encoding="utf-8") as f:
        after = f.read()
    assert before == after
