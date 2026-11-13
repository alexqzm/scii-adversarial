# -*- coding: utf-8 -*-
"""Сравнение k-стойкости двух прогонов adv.analysis (например, семантики гейта 0.1.5 и 0.1.7).

    ADV_GATE_SEMANTICS=0.1.7 python -m adv.analysis --out results/gate-0.1.7/analysis.json
    python -m adv.kdiff results/analysis.json results/gate-0.1.7/analysis.json > results/gate-0.1.7/summary.md
"""
from __future__ import annotations

import json
import sys

GOALS = ["Ц1", "Ц2", "Ц3", "Ц4", "Ц5", "Ц6"]
RULES = ["П1", "П2", "П3", "П4", "П5", "П6", "П7", "П8", "П9", "П10", "П11"]
OUT = {"admit": "допуск", "reach": "допуск или ручное рассмотрение"}


def _k(x):
    return "∞" if x is None else str(x)


def main(a_path: str, b_path: str) -> int:
    with open(a_path, encoding="utf-8") as f:
        a = json.load(f)
    with open(b_path, encoding="utf-8") as f:
        b = json.load(f)
    print("# Изменения k-стойкости\n")
    print("До: `%s`. После: `%s`. Цели %s.\n" % (a_path, b_path, ", ".join(GOALS)))
    print("| Вариант | Группировка | Правило | Исход | До | После |\n|---|---|---|---|---|---|")
    for dep in a["deployments"]:
        for grp in a["deployments"][dep]:
            fa, fb = a["deployments"][dep][grp]["families"], b["deployments"][dep][grp]["families"]
            for r in RULES:
                for out in OUT:
                    va = [fa[g][r][out]["k"] for g in GOALS]
                    vb = [fb[g][r][out]["k"] for g in GOALS]
                    if va != vb:
                        print("| %s | %s | %s | %s | %s | %s |" % (dep, grp, r, OUT[out], " ".join(map(_k, va)),
                                                                  " ".join(map(_k, vb))))
    print("\nПодлинные неполные записи без изменений: %s. Компенсационная атака D3 без изменений: %s."
          % ("да" if a["availability"] == b["availability"] else "нет",
             "да" if a["compensation_D3"] == b["compensation_D3"] else "нет"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
