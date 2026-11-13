# -*- coding: utf-8 -*-
"""Сводка результатов results/summary.md и итог по гипотезам протокола (Г0–Г8, В5).

Все числа берутся из results/*.json, которые пишут adv.analysis, adv.monotonicity, adv.emulate и adv.mutate.

    python -m adv.report
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
GOALS = ["Ц1", "Ц2", "Ц3", "Ц4", "Ц5", "Ц6"]
RULES = ["П1", "П2", "П3", "П4", "П5", "П6", "П7", "П8", "П9", "П10", "П11"]
LETTER = {"допуск": "Д", "ручное рассмотрение": "Р", "запрос свидетельств": "З", "отказ": "О"}


def _load(name: str) -> Optional[dict]:
    p = os.path.join(RES, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _k(x) -> str:
    return "∞" if x is None else str(x)


def k_table(fam: dict, outcome: str = "admit") -> List[str]:
    rows = ["| Правило | " + " | ".join(GOALS) + " |", "|---|" + "---|" * len(GOALS)]
    for r in RULES:
        rows.append("| %s | %s |" % (r, " | ".join(_k(fam[g][r][outcome]["k"]) for g in GOALS)))
    return rows


def k_pair_table(fam: dict) -> List[str]:
    rows = ["| Правило | " + " | ".join(GOALS) + " |", "|---|" + "---|" * len(GOALS)]
    for r in RULES:
        cells = []
        for g in GOALS:
            a, b = fam[g][r]["admit"]["k"], fam[g][r]["reach"]["k"]
            cells.append(_k(a) if a == b else "%s (%s)" % (_k(a), _k(b)))
        rows.append("| %s | %s |" % (r, " | ".join(cells)))
    return rows


def hypotheses(an: dict, mono: Optional[dict], pmi: Optional[dict], goals: Optional[dict],
               mut: Optional[dict]) -> List[dict]:
    out = []
    D1 = an["deployments"]["D1"]["separate"]
    fam1 = D1["families"]
    dom1 = D1["dominance"]
    # Г0
    if pmi:
        ok = pmi["states_equal"] == pmi["states_total"] and pmi["decisions_equal"] == pmi["decisions_total"]
        out.append({"id": "Г0", "ok": ok, "text": "состояния %d из %d, решения %d из %d"
                    % (pmi["states_equal"], pmi["states_total"], pmi["decisions_equal"], pmi["decisions_total"])})
    # Г1
    g1 = all(an["deployments"][d][grp]["dominance"]["П10"]["П5"]["not_weaker"]
             for d in an["deployments"] for grp in an["deployments"][d])
    out.append({"id": "Г1", "ok": g1, "text": "Succ_П10 ⊆ Succ_П5 во всех развёртываниях и группировках"})
    # Г2
    dominates = all(dom1["П10"][r]["not_weaker"] for r in RULES[:6])
    strict_k = {r: [g for g in GOALS if (fam1[g]["П10"]["admit"]["k"] or 99) > (fam1[g][r]["admit"]["k"] or 99)
                    or (fam1[g]["П10"]["admit"]["k"] is None and fam1[g][r]["admit"]["k"] is not None)]
                for r in RULES[:6]}
    g2 = dominates and all(strict_k[r] for r in RULES[:6])
    out.append({"id": "Г2", "ok": g2, "text": "SCII не слабее П1–П6; цели со строго большим k: " +
                "; ".join("%s: %s" % (r, ", ".join(v)) for r, v in strict_k.items())})
    # Г3
    eq = all(dom1[a][b]["not_weaker"] for a in ("П7", "П8", "П9", "П10", "П11")
             for b in ("П7", "П8", "П9", "П10", "П11"))
    out.append({"id": "Г3", "ok": eq, "text": "в D1 семейства П7–П11 равны"})
    # Г4
    av = an["availability"]["D1"]["incomplete"]
    rej = {r: av[r]["отказ"] for r in ("П6", "П7", "П10")}
    out.append({"id": "Г4", "ok": rej["П10"] < rej["П6"] and rej["П10"] < rej["П7"],
                "text": "отказов среди %d неполных подлинных записей: SCII %d, П6 %d, П7 %d"
                % (an["availability"]["D1"]["incomplete_records"], rej["П10"], rej["П6"], rej["П7"])})
    # Г5
    lower = [g for g in GOALS if fam1[g]["П10"]["reach"]["k"] is not None and
             (fam1[g]["П10"]["admit"]["k"] is None or fam1[g]["П10"]["reach"]["k"] < fam1[g]["П10"]["admit"]["k"])]
    out.append({"id": "Г5", "ok": bool(lower), "text": "k^rev < k для целей: %s" % (", ".join(lower) or "нет")})
    # Г6
    fam2 = an["deployments"]["D2"]["separate"]["families"]
    applicable = [r for r in RULES if r not in ("П4", "П6")]
    g6 = all(fam2["Ц1"][r]["admit"]["k"] == 1 for r in applicable) and all(
        fam2["Ц1"][r]["admit"]["k"] is None for r in ("П4", "П6"))
    out.append({"id": "Г6", "ok": g6, "text": "D2: k(Ц1) = 1 для %s; П4 и П6 не допускают эталон" % ", ".join(applicable)})
    # Г7
    if goals:
        b, s = goals["best"], goals["singles"]
        ok = (b["states_equal"] == b["bundles"] == b["decisions_equal"] and
              s["states_equal"] == s["bundles"] == s["decisions_equal"])
        out.append({"id": "Г7", "ok": ok, "text": "лучшие записи: %d комплектов, состояния %d, решения %d; "
                    "одиночные действия: %d, %d, %d" % (b["bundles"], b["states_equal"], b["decisions_equal"],
                                                        s["bundles"], s["states_equal"], s["decisions_equal"])})
    # Г8
    if mut:
        viol = sum(v["нарушений_Г8"] for v in mut["summary"].values())
        total = sum(v["мутаций"] - v["неприменимо"] for v in mut["summary"].values())
        crashes = sum(v["авария"] for v in mut["summary"].values())
        oom = sum(1 for r in mut["rows"] if r.get("outcome") == "авария" and r.get("exit") == -9)
        hangs = sum(v["зависание"] for v in mut["summary"].values())
        out.append({"id": "Г8", "ok": viol == 0, "text": "искажённых комплектов %d, допусков неподлинного образа %d, "
                    "аварий %d (из них %d с исчерпанием памяти), зависаний %d" % (total, viol, crashes, oom, hangs)})
    # В5
    comp = an["compensation_D3"]
    extra = {g: v["П10_minus_П7_count"] for g, v in comp.items()}
    out.append({"id": "В5", "ok": None, "text": "D3: наборов, успешных против SCII и неуспешных против П7: " +
                ", ".join("%s %d" % (g, n) for g, n in extra.items())})
    # монотонность
    if mono:
        v = sum(x[0] + x[1] for d in ("D1", "D2") for part in ("exhaustive", "sample")
                for x in mono[d][part]["violations"].values())
        out.append({"id": "разд. 3.4", "ok": v == 0, "text": "нарушений монотонности %d (полный перебор %d записей "
                    "и выборка %d записей в D1 и D2)" % (v, mono["D1"]["exhaustive"]["records"],
                                                          mono["D1"]["sample"]["records"])})
    return out


def main() -> int:
    an = _load("analysis.json")
    mono, pmi_r, goals_r, mut = (_load("monotonicity.json"), _load("emulation.json"),
                                 _load("emulation.json"), _load("mutation.json"))
    pmi = pmi_r.get("pmi") if pmi_r else None
    goals = goals_r.get("goals") if goals_r else None
    L = ["# Результаты scii-adversarial", "",
         "Сводка генерируется программой `python -m adv.report` из results/*.json. Протокол: docs/PROTOCOL.md "
         "(SHA-256 `%s`). scii-gate: коммит `%s`, версия %s." % (an["protocol_sha256"], an["scii_gate"]["commit"],
                                                                  an["scii_gate"]["version"]), ""]
    L += ["## Гипотезы", "", "| Код | Итог | Основание |", "|---|---|---|"]
    for h in hypotheses(an, mono, pmi, goals, mut):
        verdict = "поисковый" if h["ok"] is None else ("подтверждена" if h["ok"] else "опровергнута")
        L.append("| %s | %s | %s |" % (h["id"], verdict, h["text"]))
    L += ["", "## Правила", ""] + ["- %s — %s" % (c, n) for c, n in an["rules"].items()]
    L += ["", "Пороги по эталону: " + "; ".join("%s: %s" % (d, ", ".join("%s %s" % kv for kv in t.items()))
                                                 for d, t in an["thresholds"].items())]
    for d in ("D1", "D2", "D3"):
        for grp, title in (("separate", "участники по отдельности"), ("org", "организационная группировка")):
            fam = an["deployments"][d][grp]["families"]
            L += ["", "## k-стойкость, %s, %s" % (d, title), "",
                  "Наименьшее число единиц компрометации для допуска неподлинного образа; в скобках — для допуска или "
                  "ручного рассмотрения, если отличается. ∞ — недостижимо.", ""]
            L += k_pair_table(fam)
    fam1 = an["deployments"]["D1"]["separate"]["families"]
    L += ["", "## Минимальные наборы компрометации, D1, SCII (П10)", ""]
    for g in GOALS:
        sets = fam1[g]["П10"]["admit"]["minimal"]
        L.append("- %s: %s" % (g, "; ".join("{%s}" % ", ".join(s) for s in sets) or "допуск недостижим"))
    rc = an["deployments"]["D1"]["separate"]["random_cost"]
    L += ["", "## Случайная стоимость, D1", "",
          "Доля из %d наборов стоимостей U[%g, %g] (seed %d), при которых наименьшая стоимость атаки на SCII не "
          "меньше / строго больше, чем на правило." % (rc["draws"], rc["range"][0], rc["range"][1], rc["seed"]), "",
          "| Цель | " + " | ".join(r for r in RULES if r != "П10") + " |", "|---|" + "---|" * 10]
    for g in GOALS + ["любая"]:
        L.append("| %s | %s |" % (g, " | ".join("%.2f / %.2f" % (rc["share_not_cheaper"][g][r],
                                                                 rc["share_strictly_dearer"][g][r])
                                               for r in RULES if r != "П10")))
    for d in ("D1", "D2"):
        av = an["availability"][d]
        L += ["", "## Подлинные неполные записи, %s" % d, "",
              "%d записей: эталон со скрытым любым подмножеством из %d предоставляемых свидетельств (%s)."
              % (av["incomplete_records"], len(av["supplied"]), ", ".join(av["supplied"])), "",
              "| Правило | Д | Р | З | О |", "|---|---|---|---|---|"]
        for r in RULES:
            c = av["incomplete"][r]
            L.append("| %s | %d | %d | %d | %d |" % (r, c["допуск"], c["ручное рассмотрение"],
                                                    c["запрос свидетельств"], c["отказ"]))
    L += ["", "## Штатные сценарии ПМИ (D1)", "", "| Сценарий | " + " | ".join(RULES) + " |",
          "|---|" + "---|" * len(RULES)]
    for sc, dec in an["benign_pmi"].items():
        L.append("| %s | %s |" % (sc, " | ".join(LETTER[dec[r]] for r in RULES)))
    L += ["", "## Компенсационные атаки, D3 (поисковый вопрос В5)", ""]
    for g, v in an["compensation_D3"].items():
        for it in v["minimal_extra"]:
            L.append("- %s, {%s}: нет %s, лишние %s, R_P^min = %.4f; решения SCII %s, строгой схемы %s"
                     % (g, ", ".join(it["units"]), ", ".join(it["missing_vs_reference"]),
                        ", ".join(it["extra_vs_reference"]), it["R_min"], it["decisions"]["П10"],
                        it["decisions"]["П7"]))
    if goals:
        L += ["", "## Эмуляция на артефактах", "",
              "- лучшие записи: %d комплектов (по развёртываниям: %s), совпали состояния %d, решения %d"
              % (goals["best"]["bundles"], ", ".join("%s %d" % (k, v["bundles"])
                                                     for k, v in goals["best_by_deployment"].items()),
                 goals["best"]["states_equal"], goals["best"]["decisions_equal"]),
              "- одиночные действия (D1): %d комплектов, совпали состояния %d, решения %d"
              % (goals["singles"]["bundles"], goals["singles"]["states_equal"], goals["singles"]["decisions_equal"]),
              "- расхождений: %d" % len(goals["mismatches"])]
    if mut:
        L += ["", "## Искажённые комплекты", "", "| Основа | Мутаций | Решение | Авария | Зависание | Неприменимо | "
              "Допуск | Нарушений Г8 |", "|---|---|---|---|---|---|---|---|"]
        for b, s in mut["summary"].items():
            L.append("| %s | %d | %d | %d | %d | %d | %d | %d |" % (b, s["мутаций"], s["решение"], s["авария"],
                                                                     s["зависание"], s["неприменимо"], s["допуск"],
                                                                     s["нарушений_Г8"]))
        bad = [r for r in mut["rows"] if r.get("outcome") in ("авария", "зависание")]
        kinds = {}
        for r in bad:
            if r["outcome"] == "зависание":
                cls = "зависание: превышено ограничение %d с" % mut["limit_s"]
            elif r.get("exit") == -9:
                cls = "авария: процесс завершён системой при исчерпании памяти (код -9)"
            else:
                cls = "авария: " + (r.get("error") or "").split(":")[0]
            fam = r["mutation"].split(":")[0].split(" — ")[0]
            if fam.startswith("поле "):
                fam = "поле неверного типа"
            if fam.startswith("запись "):
                fam = "запись свидетельства — строка"
            kinds.setdefault(cls, {}).setdefault(fam, 0)
            kinds[cls][fam] += 1
        if kinds:
            L += ["", "Виды аварий и зависаний (класс, искажения и их число):", ""]
            for cls, fams in sorted(kinds.items(), key=lambda kv: -sum(kv[1].values())):
                L.append("- %s (%d): %s" % (cls, sum(fams.values()), ", ".join(
                    "%s %d" % (f, n) for f, n in sorted(fams.items(), key=lambda kv: -kv[1]))))
    with open(os.path.join(RES, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("записано results/summary.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
