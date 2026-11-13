# -*- coding: utf-8 -*-
"""Проверка монотонности индикаторов «допуск» и «допуск или ручное рассмотрение» по порядку F < N < P
(протокол, разд. 3.4). На ней держится переход к лучшей записи нарушителя.

  1. Полный перебор по 12 предоставляемым свидетельствам (3^12 = 531 441 запись) при P у s52 и s53 и N
     у s11, s12, s54: решения всех правил для каждой записи и проверка каждого одиночного повышения.
  2. Случайная выборка 100 000 записей по всем 17 свидетельствам (seed 20240628) с проверкой каждого
     одиночного повышения.

Решения считает эталонная реализация (scii/model.py гейта и adv/rules.py), без векторизации.

    python -m adv.monotonicity --out results/monotonicity.json [--sample 100000] [--jobs 2]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from multiprocessing import Pool

from .rules import ADMIT, REVIEW, RULESETS, RuleSet
from .semantics import EVIDENCE, N, P, F

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUPPLIED = ["s13", "s14", "s21", "s22", "s23", "s24", "s31", "s32", "s41", "s42", "s43", "s51"]
STATES = [F, N, P]
UP = {F: N, N: P}
SEED = 20240628


def _ind(dec: str):
    return (dec == ADMIT, dec in (ADMIT, REVIEW))


def _decide_codes(args):
    """Решения всех правил для блока кодов полного перебора (кортеж индикаторов по правилам)."""
    d_code, lo, hi = args
    rs = RULESETS[d_code]
    base = {e: N for e in ("s11", "s12", "s54")}
    base.update({"s52": P, "s53": P})
    out = []
    for code in range(lo, hi):
        st = dict(base)
        x = code
        for e in SUPPLIED:
            st[e] = STATES[x % 3]
            x //= 3
        dec = rs.all(st)
        out.append(tuple(_ind(dec[r]) for r in RuleSet.CODES))
    return out


def exhaustive(d_code: str, jobs: int) -> dict:
    n = 3 ** len(SUPPLIED)
    step = 20_000
    chunks = [(d_code, lo, min(lo + step, n)) for lo in range(0, n, step)]
    with Pool(jobs) as pool:
        parts = pool.map(_decide_codes, chunks)
    ind = [t for part in parts for t in part]
    viol = {r: [0, 0] for r in RuleSet.CODES}
    checks = 0
    for code in range(n):
        x, pw = code, 1
        for _i in range(len(SUPPLIED)):
            digit = x % 3
            if digit < 2:
                up = code + pw
                checks += 1
                for j, r in enumerate(RuleSet.CODES):
                    a0, r0 = ind[code][j]
                    a1, r1 = ind[up][j]
                    viol[r][0] += a0 and not a1
                    viol[r][1] += r0 and not r1
            x //= 3
            pw *= 3
    return {"records": n, "raises": checks, "violations": viol}


def _sample_block(args):
    d_code, seed, count = args
    rs = RULESETS[d_code]
    rng = random.Random(seed)
    viol = {r: [0, 0] for r in RuleSet.CODES}
    raises = 0
    for _ in range(count):
        st = {e: rng.choice(STATES) for e in EVIDENCE}
        d0 = rs.all(st)
        for e in EVIDENCE:
            if st[e] in UP:
                st2 = dict(st)
                st2[e] = UP[st[e]]
                d1 = rs.all(st2)
                raises += 1
                for r in RuleSet.CODES:
                    a0, r0 = _ind(d0[r])
                    a1, r1 = _ind(d1[r])
                    viol[r][0] += a0 and not a1
                    viol[r][1] += r0 and not r1
    return raises, viol


def sample(d_code: str, count: int, jobs: int) -> dict:
    per = count // jobs
    blocks = [(d_code, SEED + i, per + (count - per * jobs if i == jobs - 1 else 0)) for i in range(jobs)]
    with Pool(jobs) as pool:
        parts = pool.map(_sample_block, blocks)
    viol = {r: [0, 0] for r in RuleSet.CODES}
    raises = 0
    for rz, v in parts:
        raises += rz
        for r in RuleSet.CODES:
            viol[r][0] += v[r][0]
            viol[r][1] += v[r][1]
    return {"records": count, "raises": raises, "violations": viol, "seed": SEED}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adv.monotonicity")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "monotonicity.json"))
    ap.add_argument("--sample", type=int, default=100_000)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--deployments", default="D1,D2")
    a = ap.parse_args(argv)
    res = {"rules": RuleSet.CODES, "indicators": ["допуск", "допуск или ручное рассмотрение"]}
    for d_code in a.deployments.split(","):
        t0 = time.time()
        res[d_code] = {"exhaustive": exhaustive(d_code, a.jobs), "sample": sample(d_code, a.sample, a.jobs),
                       "thresholds": RULESETS[d_code].thresholds()}
        res[d_code]["seconds"] = round(time.time() - t0, 1)
        total = sum(v[0] + v[1] for part in ("exhaustive", "sample") for v in res[d_code][part]["violations"].values())
        print("%s: нарушений монотонности %d (%.0f с)" % (d_code, total, res[d_code]["seconds"]))
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    bad = sum(v[0] + v[1] for d in a.deployments.split(",") for part in ("exhaustive", "sample")
              for v in res[d][part]["violations"].values())
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
