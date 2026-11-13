# -*- coding: utf-8 -*-
"""Аналитическая часть эксперимента (протокол, разд. 5 и 6): семейства успешных наборов компрометации,
k-стойкость, доминирование, случайная стоимость, путь к человеку, цена для подлинных выпусков,
пороговая кривая и поиск компенсационных атак в D3.

    python -m adv.analysis --out results/analysis.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import subprocess
from typing import Dict, FrozenSet, List, Tuple

from .rules import (ADMIT, BOTTOM, PROFILE, REJECT, REQUEST, REVIEW, RULESETS, SCII_GATE, SCII_VERSION, THETA_TOL,
                    RuleSet, additive, binary, gate, interval, interval_box)
from .semantics import (DEPLOYMENTS, EVIDENCE, GOALS, GROUPINGS, N, P, best_record, compromise_sets,
                        members, units)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = RuleSet.CODES
SEED = 20240628
COST_DRAWS = 10_000
COST_RANGE = (1.0, 10.0)


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _gate_commit() -> str:
    try:
        return subprocess.run(["git", "-C", SCII_GATE, "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "неизвестен"


def rec_key(st: Dict[str, str]) -> str:
    return "".join(st[e] for e in EVIDENCE)


# ---------------- семейства успешных наборов ----------------
def evaluate_sets(d_code: str, grouping: str) -> Dict[str, List[dict]]:
    """Для каждой цели: все наборы единиц с лучшей записью и решениями правил на ней."""
    d, rs = DEPLOYMENTS[d_code], RULESETS[d_code]
    out = {}
    for g in GOALS:
        rows = []
        for U in compromise_sets(d, grouping, g):
            C = members(d, grouping, U)
            st = best_record(d, g, C)
            rows.append({"units": sorted(U), "participants": sorted(C), "record": rec_key(st),
                         "decisions": rs.all(st)})
        out[g] = rows
    return out


def minimal(sets: List[FrozenSet[str]]) -> List[FrozenSet[str]]:
    sets = sorted(set(sets), key=lambda s: (len(s), sorted(s)))
    out: List[FrozenSet[str]] = []
    for s in sets:
        if not any(m <= s for m in out):
            out.append(s)
    return out


def family(rows: List[dict], rule: str, outcome: str) -> List[FrozenSet[str]]:
    ok = {ADMIT} if outcome == "admit" else {ADMIT, REVIEW}
    return [frozenset(r["units"]) for r in rows if r["decisions"][rule] in ok]


def summarize_families(rows_by_goal: Dict[str, List[dict]]) -> dict:
    out = {}
    for g, rows in rows_by_goal.items():
        out[g] = {}
        for rule in RULES:
            out[g][rule] = {}
            for outcome in ("admit", "reach"):
                fam = family(rows, rule, outcome)
                mins = minimal(fam)
                out[g][rule][outcome] = {"k": min((len(s) for s in mins), default=None),
                                         "minimal": [sorted(s) for s in mins], "count": len(fam)}
    return out


def dominance(rows_by_goal: Dict[str, List[dict]]) -> Dict[str, Dict[str, dict]]:
    """dom[R1][R2]: Succ_R1 ⊆ Succ_R2 по всем целям (R1 не слабее R2) и строгость."""
    fam = {r: {g: set(family(rows, r, "admit")) for g, rows in rows_by_goal.items()} for r in RULES}
    out = {}
    for r1 in RULES:
        out[r1] = {}
        for r2 in RULES:
            sub = all(fam[r1][g] <= fam[r2][g] for g in GOALS)
            strict = sub and any(fam[r1][g] < fam[r2][g] for g in GOALS)
            out[r1][r2] = {"not_weaker": sub, "strictly_stronger": strict}
    return out


# ---------------- случайная стоимость (разд. 5.4) ----------------
def random_cost(fams: Dict[str, Dict[str, dict]], unit_names: List[str]) -> dict:
    rng = random.Random(SEED)
    lo, hi = COST_RANGE
    mins = {g: {r: [tuple(s) for s in fams[g][r]["admit"]["minimal"]] for r in RULES} for g in GOALS}
    ge = {g: {r: 0 for r in RULES} for g in GOALS + ["любая"]}
    gt = {g: {r: 0 for r in RULES} for g in GOALS + ["любая"]}
    inf = float("inf")
    for _ in range(COST_DRAWS):
        cost = {u: rng.uniform(lo, hi) for u in unit_names}
        best = {}
        for g in GOALS:
            best[g] = {r: min((sum(cost[u] for u in s) for s in mins[g][r]), default=inf) for r in RULES}
        best["любая"] = {r: min(best[g][r] for g in GOALS) for r in RULES}
        for g, row in best.items():
            for r in RULES:
                a, b = row["П10"], row[r]
                ge[g][r] += a >= b
                gt[g][r] += a > b
    return {"draws": COST_DRAWS, "seed": SEED, "range": list(COST_RANGE),
            "share_not_cheaper": {g: {r: ge[g][r] / COST_DRAWS for r in RULES} for g in ge},
            "share_strictly_dearer": {g: {r: gt[g][r] / COST_DRAWS for r in RULES} for g in gt}}


# ---------------- цена для подлинных выпусков (разд. 5.6) ----------------
def genuine_records(d_code: str) -> List[Dict[str, str]]:
    d = DEPLOYMENTS[d_code]
    sup = d.supplied
    out = []
    for mask in range(1 << len(sup)):
        st = dict(d.reference)
        for i, e in enumerate(sup):
            if mask >> i & 1:
                st[e] = N
        out.append(st)
    return out


def availability(d_code: str) -> dict:
    rs = RULESETS[d_code]
    recs = genuine_records(d_code)
    counts = {r: {ADMIT: 0, REVIEW: 0, REQUEST: 0, REJECT: 0} for r in RULES}
    incomplete = {r: {ADMIT: 0, REVIEW: 0, REQUEST: 0, REJECT: 0} for r in RULES}
    full = rec_key(DEPLOYMENTS[d_code].reference)
    for st in recs:
        dec = rs.all(st)
        for r in RULES:
            counts[r][dec[r]] += 1
            if rec_key(st) != full:
                incomplete[r][dec[r]] += 1
    return {"records": len(recs), "supplied": DEPLOYMENTS[d_code].supplied, "all": counts,
            "incomplete": incomplete, "incomplete_records": len(recs) - 1}


def benign_pmi() -> dict:
    """7 штатных сценариев ПМИ (D1), состояния из testbed/plan.json scii-gate."""
    with open(os.path.join(SCII_GATE, "testbed", "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    rs = RULESETS["D1"]
    out = {}
    for sc in plan["scenarios"]:
        if sc["id"][0] in "OB":
            out[sc["id"]] = rs.all(sc["expect_states"])
    return out


# ---------------- пороговая кривая (разд. 5.7, поисковая) ----------------
def _features(st: Dict[str, str]) -> Tuple:
    g = gate(PROFILE, st)
    b = binary(PROFILE, st)
    rmin, rmax = interval(PROFILE, st)
    bmin, bmax = interval_box(PROFILE, st)
    return (g, b, rmin, rmax, bmin, bmax, float(additive(st)))


def sweep(d_code: str, rows_by_goal: Dict[str, List[dict]]) -> dict:
    """Для П8–П11: все точки смены решения по θ. Для каждого θ доля допущенных подлинных неполных записей и
    k-стойкость по целям (наборы единиц, группировка separate)."""
    d = DEPLOYMENTS[d_code]
    gen = [st for st in genuine_records(d_code) if rec_key(st) != rec_key(d.reference)]
    # лучшие записи атак: уникальные записи и минимальный размер набора, который к ним приводит
    attack = {}
    for g, rows in rows_by_goal.items():
        for r in rows:
            attack.setdefault((g, r["record"]), []).append(len(r["units"]))
    att_f = [(_features(dict(zip(EVIDENCE, k))), g, attack[(g, k)]) for (g, k) in attack]

    def admit_mask(feats, rule, theta):
        g, b, rmin, rmax, bmin, bmax, m = feats
        if rule == "П9":
            return rmin >= theta - THETA_TOL
        if g == BOTTOM or g == 0:
            return False
        if rule == "П10":
            return b == 1 and rmin >= theta - THETA_TOL
        if rule == "П11":
            return b == 1 and bmin >= theta - THETA_TOL
        if rule == "П8":
            return b == 1 and m >= theta - 1e-12
        raise KeyError(rule)

    idx = {"П9": 2, "П10": 2, "П11": 4, "П8": 6}
    out = {}
    gen_feats = [_features(st) for st in gen]
    for rule, i in idx.items():
        vals = sorted({round(f[i], 12) for f in gen_feats} | {round(f[i], 12) for f, _, _ in att_f} | {0.0, 1.0})
        pts = []
        for theta in vals:
            av = sum(admit_mask(f, rule, theta) for f in gen_feats) / len(gen_feats)
            k = {}
            for g in GOALS:
                ks = [min(sizes) for f, gg, sizes in att_f if gg == g and admit_mask(f, rule, theta)]
                k[g] = min(ks) if ks else None
            pts.append({"theta": theta, "availability": av, "k": k})
        out[rule] = pts
    return out


# ---------------- компенсационные атаки в D3 (В5, поисковый) ----------------
def compensation(rows_by_goal: Dict[str, List[dict]]) -> dict:
    ref = DEPLOYMENTS["D3"].reference
    out = {}
    for g, rows in rows_by_goal.items():
        f10 = set(family(rows, "П10", "admit"))
        f7 = set(family(rows, "П7", "admit"))
        extra = minimal([s for s in f10 - f7])
        items = []
        for s in extra:
            r = next(x for x in rows if frozenset(x["units"]) == s)
            st = dict(zip(EVIDENCE, r["record"]))
            items.append({"units": sorted(s), "record": r["record"],
                          "missing_vs_reference": [e for e in EVIDENCE if ref[e] == P and st[e] != P],
                          "extra_vs_reference": [e for e in EVIDENCE if ref[e] != P and st[e] == P],
                          "R_min": interval(PROFILE, st)[0], "R_max": interval(PROFILE, st)[1],
                          "decisions": r["decisions"]})
        out[g] = {"П10_minus_П7_count": len(f10 - f7), "П7_minus_П10_count": len(f7 - f10), "minimal_extra": items}
    return out


def run() -> dict:
    res = {"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "protocol_sha256": _sha256(os.path.join(ROOT, "docs", "PROTOCOL.md")),
           "scii_gate": {"commit": _gate_commit(), "version": SCII_VERSION},
           "rules": {c: RuleSet.NAMES[c] for c in RULES},
           "thresholds": {k: rs.thresholds() for k, rs in RULESETS.items()},
           "deployments": {}, "availability": {}, "sweep": {}}
    rows_cache = {}
    for d_code in DEPLOYMENTS:
        res["deployments"][d_code] = {}
        for grouping in GROUPINGS:
            rows = evaluate_sets(d_code, grouping)
            rows_cache[(d_code, grouping)] = rows
            fams = summarize_families(rows)
            unit_names = list(units(DEPLOYMENTS[d_code], grouping))
            res["deployments"][d_code][grouping] = {
                "units": {u: list(m) for u, m in units(DEPLOYMENTS[d_code], grouping).items()},
                "families": fams, "dominance": dominance(rows),
                "random_cost": random_cost(fams, unit_names) if grouping == "separate" else None,
                "distinct_records": {g: len({r["record"] for r in rows[g]}) for g in GOALS}}
        res["availability"][d_code] = availability(d_code)
    res["benign_pmi"] = benign_pmi()
    res["sweep"]["D1"] = sweep("D1", rows_cache[("D1", "separate")])
    res["compensation_D3"] = compensation(rows_cache[("D3", "separate")])
    rows1 = rows_cache[("D1", "separate")]
    res["binary_admit_vs_scii_reach_D1"] = {
        g: {"binary_admit": len(family(rows1[g], "П5", "admit")), "scii_reach": len(family(rows1[g], "П10", "reach")),
            "equal": set(family(rows1[g], "П5", "admit")) == set(family(rows1[g], "П10", "reach")),
            "scii_reach_subset": set(family(rows1[g], "П10", "reach")) <= set(family(rows1[g], "П5", "admit"))}
        for g in GOALS}
    res["attack_records"] = {
        d_code: {g: sorted({(r["record"]) for r in rows_cache[(d_code, "separate")][g]}) for g in GOALS}
        for d_code in DEPLOYMENTS}
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adv.analysis")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "analysis.json"))
    a = ap.parse_args(argv)
    res = run()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1, default=str)
    print("записано %s" % a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
