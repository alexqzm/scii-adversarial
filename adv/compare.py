# -*- coding: utf-8 -*-
"""Сверка свежего прогона с результатами в results/ без изменчивых полей (время, длительность, версия cosign).

    python -m adv.compare analysis     NEW.json [results/analysis.json]
    python -m adv.compare monotonicity NEW.json [results/monotonicity.json]
    python -m adv.compare emulation    NEW.json [results/emulation.json]
    python -m adv.compare mutation     NEW.json [results/mutation.json] [--subset]

--subset для mutation: сверяются только искажения, которые есть в обоих файлах (в CI пропускаются искажения,
исчерпывающие память машины, см. adv.mutate --skip-memory).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VOLATILE = {"generated", "seconds", "cosign", "elapsed_s", "time_utc"}


def strip(obj):
    if isinstance(obj, dict):
        return {k: strip(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [strip(x) for x in obj]
    return obj


def _diff(a, b, path="", out=None, limit=20):
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append("%s/%s: есть только в %s" % (path, k, "новом" if k in a else "сохранённом"))
            else:
                _diff(a[k], b[k], "%s/%s" % (path, k), out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append("%s: длина %d и %d" % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(x, y, "%s[%d]" % (path, i), out, limit)
    elif a != b:
        out.append("%s: %r и %r" % (path, a, b))
    return out


def mutation_rows(res):
    """Сравниваемые поля искажённого комплекта. Дайджест восстановленного образа сам по себе не сравнивается:
    у неподлинного образа он зависит от ключей, перевыпускаемых при каждом прогоне (например, когда пакет
    подменён аттестацией или в образе нет дескриптора и поле подписи не обнуляется). Сравнивается признак
    «образ подлинный», на котором держится Г8."""
    keep = ("outcome", "exit", "decision", "states", "violation_g8", "error")
    genuine = res.get("genuine_image_sha256")
    out = {}
    for r in res["rows"]:
        row = {k: r.get(k) for k in keep}
        row["image_genuine"] = None if r.get("image_sha256") is None else r["image_sha256"] == genuine
        out[(r["base"], r["mutation"])] = row
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adv.compare")
    ap.add_argument("kind", choices=["analysis", "monotonicity", "emulation", "mutation"])
    ap.add_argument("new")
    ap.add_argument("saved", nargs="?")
    ap.add_argument("--subset", action="store_true")
    a = ap.parse_args(argv)
    saved = a.saved or os.path.join(ROOT, "results", "%s.json" % a.kind)
    with open(a.new, encoding="utf-8") as f:
        new = json.load(f)
    with open(saved, encoding="utf-8") as f:
        old = json.load(f)
    if a.kind == "mutation":
        n, o = mutation_rows(new), mutation_rows(old)
        if a.subset:
            common = set(n) & set(o)
            missing = sorted(set(n) - set(o))
            n = {k: n[k] for k in common}
            o = {k: o[k] for k in common}
            if missing:
                print("новых искажений нет в сохранённом прогоне: %d" % len(missing))
                return 1
        diffs = _diff({"%s|%s" % k: v for k, v in n.items()}, {"%s|%s" % k: v for k, v in o.items()})
    else:
        diffs = _diff(strip(new), strip(old))
    if diffs:
        print("расхождения с %s:" % saved)
        for d in diffs:
            print("  " + d)
        return 1
    print("%s: совпадает с %s" % (a.kind, os.path.relpath(saved, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
