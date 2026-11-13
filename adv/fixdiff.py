# -*- coding: utf-8 -*-
"""Результаты до и после исправления scii-gate (протокол, разд. 8: дефекты исправляются новой версией
с согласия автора, результаты приводятся до и после исправления).

    python -m adv.fixdiff --before results --after results/after-0.1.6 --gate "scii-gate 0.1.6 (97a78c1)" \
        --out results/after-0.1.6/summary.md
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _kind(r: dict) -> str:
    if r["outcome"] == "авария":
        return "авария (исчерпание памяти)" if r.get("exit") == -9 else "авария (исключение)"
    return r["outcome"]


def _mutation_stats(rows) -> dict:
    secs = [r["seconds"] for r in rows if r.get("seconds") is not None]
    return {
        "outcomes": collections.Counter(_kind(r) for r in rows),
        "decisions": collections.Counter(r.get("decision") for r in rows if r["outcome"] == "решение"),
        "g8": sum(1 for r in rows if r.get("violation_g8")),
        "max_s": max(secs) if secs else None,
    }


def report(before: str, after: str, gate: str) -> str:
    mb, ma = _load(os.path.join(before, "mutation.json")), _load(os.path.join(after, "mutation.json"))
    eb, ea = _load(os.path.join(before, "emulation.json")), _load(os.path.join(after, "emulation.json"))
    rb = {(r["base"], r["mutation"]): r for r in mb["rows"]}
    ra = {(r["base"], r["mutation"]): r for r in ma["rows"]}
    if set(rb) != set(ra):
        raise SystemExit("наборы искажений до и после различаются")
    sb, sa = _mutation_stats(mb["rows"]), _mutation_stats(ma["rows"])
    L = ["# Результаты после исправления scii-gate", "",
         "Сводка генерируется программой `python -m adv.fixdiff`. До исправления: scii-gate 0.1.5 (d210811), "
         "results/. После: %s." % gate, "",
         "## Эмуляция на артефактах", "",
         "| Проверка | До | После |", "|---|---|---|"]
    L.append("| Г0: состояния 16 сценариев ПМИ | %d из %d | %d из %d |" % (
        eb["pmi"]["states_equal"], eb["pmi"]["states_total"], ea["pmi"]["states_equal"], ea["pmi"]["states_total"]))
    L.append("| Г0: решения 16 сценариев ПМИ | %d из %d | %d из %d |" % (
        eb["pmi"]["decisions_equal"], eb["pmi"]["decisions_total"], ea["pmi"]["decisions_equal"],
        ea["pmi"]["decisions_total"]))
    L.append("| Г7: комплекты лучших записей | %d | %d |" % (eb["goals"]["best"]["bundles"], ea["goals"]["best"]["bundles"]))
    L.append("| Г7: комплекты одиночных действий | %d | %d |" % (eb["goals"]["singles"]["bundles"],
                                                               ea["goals"]["singles"]["bundles"]))
    L.append("| Г7: расхождения модели и модуля допуска | %d | %d |" % (len(eb["goals"]["mismatches"]),
                                                                       len(ea["goals"]["mismatches"])))
    L += ["", "## Искажённые комплекты (%d)" % len(rb), "",
          "| Исход | До | После |", "|---|---|---|"]
    for k in ("решение", "авария (исключение)", "авария (исчерпание памяти)", "зависание"):
        L.append("| %s | %d | %d |" % (k, sb["outcomes"].get(k, 0), sa["outcomes"].get(k, 0)))
    for k in ("допуск", "ручное рассмотрение", "запрос свидетельств", "отказ"):
        L.append("| решение «%s» | %d | %d |" % (k, sb["decisions"].get(k, 0), sa["decisions"].get(k, 0)))
    L.append("| допуск неподлинного образа (Г8) | %d | %d |" % (sb["g8"], sa["g8"]))
    L.append("| наибольшее время проверки, с | %.1f | %.1f |" % (sb["max_s"], sa["max_s"]))
    same, st_only, dec = 0, [], []
    moved = collections.Counter()
    for k in sorted(rb):
        x, y = rb[k], ra[k]
        if x["outcome"] == "решение" and y["outcome"] == "решение":
            if x["decision"] != y["decision"]:
                dec.append((k, x["decision"], y["decision"]))
            elif x["states"] != y["states"]:
                st_only.append(k)
            else:
                same += 1
        else:
            moved[(_kind(x), _kind(y), y.get("decision"))] += 1
    cats = collections.Counter(re.sub(r":.*", "", k[1]) for k in st_only + [d[0] for d in dec])
    L += ["", "Комплекты, получившие решение до исправления: %d. Совпали состояния и решение: %d. "
          "Изменились только состояния: %d. Изменилось решение: %d." % (same + len(st_only) + len(dec), same,
                                                                        len(st_only), len(dec)),
          "", "Виды искажений с изменениями: " + ", ".join("%s (%d)" % kv for kv in sorted(cats.items())) + ".",
          "", "| Комплект | Искажение | До | После |", "|---|---|---|---|"]
    for (base, mut), d0, d1 in dec:
        L.append("| %s | %s | %s | %s |" % (base, mut, d0, d1))
    L += ["", "Комплекты без решения до исправления:", "", "| До | После | Решение | Число |", "|---|---|---|---|"]
    for (k0, k1, d), cnt in sorted(moved.items(), key=lambda t: -t[1]):
        L.append("| %s | %s | %s | %d |" % (k0, k1, d or "", cnt))
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adv.fixdiff")
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--gate", required=True, help="версия и коммит scii-gate после исправления")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    md = report(a.before, a.after, a.gate)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
