# -*- coding: utf-8 -*-
"""Пересчёт чисел статьи о стойкости правила допуска SCII (ВАК-6) из results/*.json.

Каждое число текста статьи берётся отсюда, поэтому расхождение текста и прогона невозможно.

    python paper/vak6/numbers.py            таблица чисел
    python paper/vak6/numbers.py --json     то же в JSON
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RES = os.path.join(ROOT, "results")
sys.path.insert(0, ROOT)
from adv.report import hypotheses  # noqa: E402
GOALS = ["Ц1", "Ц2", "Ц3", "Ц4", "Ц5", "Ц6"]
RULES = ["П1", "П2", "П3", "П4", "П5", "П6", "П7", "П8", "П9", "П10", "П11"]


def load(name):
    with open(os.path.join(RES, name), encoding="utf-8") as f:
        return json.load(f)


def pct(x):
    return "%d %%" % round(100 * x)


def numbers():
    an, mono, emu, mut = load("analysis.json"), load("monotonicity.json"), load("emulation.json"), load("mutation.json")
    fam = an["deployments"]["D1"]["separate"]["families"]
    k = {r: [fam[g][r]["admit"]["k"] for g in GOALS] for r in RULES}
    reach = {r: [fam[g][r]["reach"]["k"] for g in GOALS] for r in RULES}
    rc = an["deployments"]["D1"]["separate"]["random_cost"]["share_strictly_dearer"]["любая"]
    nc = an["deployments"]["D1"]["separate"]["random_cost"]["share_not_cheaper"]["любая"]
    av = an["availability"]["D1"]["incomplete"]
    org = an["deployments"]["D1"]["org"]["families"]
    d3 = an["deployments"]["D3"]["separate"]["families"]
    comp = an["compensation_D3"]["Ц1"]["minimal_extra"][0]
    rows = mut["rows"]
    crash_exc = sum(1 for r in rows if r.get("outcome") == "авария" and r.get("exit") == 1)
    oom = sum(1 for r in rows if r.get("outcome") == "авария" and r.get("exit") == -9)
    hang = sum(1 for r in rows if r.get("outcome") == "зависание")

    def stronger(a, b):
        """k метода (a) строго больше k правила (b); None означает недостижимость (∞)."""
        return b is not None and (a is None or a > b)
    return {
        "k_admit_D1": k, "k_reach_D1": reach,
        "strict_k_vs_scii": {r: sum(1 for a, b in zip(k["П10"], k[r]) if stronger(a, b)) for r in RULES[:6]},
        "hypotheses": {h["id"]: h["ok"] for h in hypotheses(an, mono, emu["pmi"], emu["goals"], mut)},
        "cost_draws": an["deployments"]["D1"]["separate"]["random_cost"]["draws"],
        "cost_not_cheaper_min": min(nc[r] for r in RULES if r != "П10"),
        "cost_dearer": {r: rc[r] for r in RULES if r != "П10"},
        "cost_dearer_pct": {r: pct(rc[r]) for r in RULES if r != "П10"},
        "org_k_scii": [org[g]["П10"]["admit"]["k"] for g in GOALS],
        "availability_D1": {r: av[r] for r in RULES},
        "genuine_incomplete": an["availability"]["D1"]["incomplete_records"],
        "d2_k_c1": {r: an["deployments"]["D2"]["separate"]["families"]["Ц1"][r]["admit"]["k"] for r in RULES},
        "d3_comp_units": comp["units"], "d3_comp_rmin": round(comp["R_min"], 3),
        "d3_c1_counts": {"П7": d3["Ц1"]["П7"]["admit"]["count"], "П10": d3["Ц1"]["П10"]["admit"]["count"],
                          "all": 2 ** (len(an["deployments"]["D3"]["separate"]["units"]) - 1)},
        "d3_c6_k": {r: d3["Ц6"][r]["admit"]["k"] for r in ("П8", "П10", "П11")},
        "binary_vs_reach": an["binary_admit_vs_scii_reach_D1"],
        "mono_records": mono["D1"]["exhaustive"]["records"], "mono_sample": mono["D1"]["sample"]["records"],
        "mono_violations": sum(x[0] + x[1] for d in ("D1", "D2") for p in ("exhaustive", "sample")
                               for x in mono[d][p]["violations"].values()),
        "g0_states": "%d из %d" % (emu["pmi"]["states_equal"], emu["pmi"]["states_total"]),
        "g0_decisions": "%d из %d" % (emu["pmi"]["decisions_equal"], emu["pmi"]["decisions_total"]),
        "emu_best": emu["goals"]["best"]["bundles"], "emu_best_by_d": {d: v["bundles"] for d, v in
                                                                     emu["goals"]["best_by_deployment"].items()},
        "emu_singles": emu["goals"]["singles"]["bundles"], "emu_mismatches": len(emu["goals"]["mismatches"]),
        "mut_total": len(rows), "mut_g8": sum(1 for r in rows if r.get("violation_g8")),
        "mut_crash_exc": crash_exc, "mut_oom": oom, "mut_hang": hang,
        "mut_decisions": sum(1 for r in rows if r.get("outcome") == "решение"),
    }


if __name__ == "__main__":
    n = numbers()
    if "--json" in sys.argv:
        print(json.dumps(n, ensure_ascii=False, indent=1))
    else:
        for key, val in n.items():
            print("%-22s %s" % (key, val))
