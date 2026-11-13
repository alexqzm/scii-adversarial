# -*- coding: utf-8 -*-
"""Модель нарушителя и правила совпадают с протоколом 1.0 и с определениями статьи ВАК-2."""
import hashlib
import itertools
import json
import os
import re
from fractions import Fraction

from adv.rules import ADMIT, REJECT, REQUEST, REVIEW, RULESETS, SCII_GATE
from adv.semantics import (DEPLOYMENTS, EVIDENCE, GOAL, GOALS, HONEST, N, P, F, PARTICIPANTS, PRODUCER,
                           best_record, compromise_sets, honest_state, members, options)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOCOL = os.path.join(ROOT, "docs", "PROTOCOL.md")


def _protocol():
    with open(PROTOCOL, encoding="utf-8") as f:
        return f.read()


def test_protocol_hash_recorded():
    with open(os.path.join(ROOT, "docs", "PROTOCOL.sha256")) as f:
        digest = f.read().split()[0]
    with open(PROTOCOL, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == digest


def test_honest_table_is_protocol_table_3_3():
    rows = {}
    for ln in _protocol().splitlines():
        m = re.match(r"^\| (s\d\d) \| ([^|]*) \|((?: [PNF] \|){6})$", ln)
        if m:
            rows[m.group(1)] = m.group(3).replace("|", " ").split()
    assert list(rows) == EVIDENCE
    for i, g in enumerate(GOALS):
        assert {e: rows[e][i] for e in EVIDENCE} == HONEST[g], g


def test_participants_are_protocol_table_3_1():
    rows = {}
    for ln in _protocol().splitlines():
        m = re.match(r"^\| ([A-Z]{2,4}) \| ([^|]+) \| ([^|]+) \| (Н\d) \|$", ln)
        if m:
            rows[m.group(1)] = re.findall(r"s\d\d", m.group(3))
    assert sorted(rows) == sorted(PARTICIPANTS)
    produced = {}
    for e, p in PRODUCER.items():
        produced.setdefault(p, []).append(e)
    for p, ev in rows.items():
        assert sorted(ev) == sorted(produced.get(p, [])), p


def test_goals_entry_points():
    assert {g: GOAL[g]["entry"] for g in GOALS} == {"Ц1": "BLD", "Ц2": "ARC", "Ц3": "DEP", "Ц4": "REPO",
                                                     "Ц5": "CH", "Ц6": "CH"}


def test_thresholds_follow_vak2_procedure():
    rs = RULESETS["D1"]
    assert (rs.theta, rs.theta_box, rs.theta_add) == (0.496, 0.27, Fraction(21, 25))
    rs2 = RULESETS["D2"]
    assert (rs2.theta, rs2.theta_box) == (0.465, 0.243)


def test_rules_reproduce_vak2_table5():
    """Счёты решений по 16 сценариям ПМИ (опасные / штатные; Д, О, Р, З) как в табл. 5 статьи ВАК-2."""
    with open(os.path.join(SCII_GATE, "testbed", "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    order = [ADMIT, REJECT, REVIEW, REQUEST]
    want = {"П5": ([1, 8, 0, 0], [4, 3, 0, 0]), "П6": ([0, 9, 0, 0], [3, 4, 0, 0]),
            "П8": ([0, 8, 0, 1], [2, 3, 0, 2]), "П9": ([0, 4, 5, 0], [2, 3, 2, 0]),
            "П10": ([0, 6, 2, 1], [2, 1, 2, 2]), "П11": ([0, 6, 2, 1], [2, 1, 2, 2])}
    rs = RULESETS["D1"]
    for code, (dang, ben) in want.items():
        got = {"A": [0] * 4, "B": [0] * 4}
        for sc in plan["scenarios"]:
            got["A" if sc["id"].startswith("A") else "B"][order.index(rs.decide(code, sc["expect_states"]))] += 1
        assert (got["A"], got["B"]) == (dang, ben), code


def test_reference_admitted_by_every_rule_except_where_impossible():
    for d_code, d in DEPLOYMENTS.items():
        dec = RULESETS[d_code].all(d.reference)
        for r, x in dec.items():
            if d_code == "D2" and r in ("П4", "П6"):
                assert x == REJECT          # без якоря IND s24 не бывает P
            else:
                assert x == ADMIT, (d_code, r)


def test_honest_states_by_deployment():
    assert honest_state(DEPLOYMENTS["D2"], "Ц1", "s24") == N
    assert honest_state(DEPLOYMENTS["D3"], "Ц1", "s12") == N
    assert honest_state(DEPLOYMENTS["D1"], "Ц6", "s11") == F


def test_actions():
    d = DEPLOYMENTS["D1"]
    assert options(d, "Ц1", "s24", frozenset({"BLD"})) == [F]
    assert options(d, "Ц1", "s24", frozenset({"BLD", "CH"})) == [F, N]
    assert options(d, "Ц1", "s24", frozenset({"BLD", "IND"})) == [F, P]
    assert options(d, "Ц6", "s14", frozenset({"CH"})) == [F, N, P]          # повтор подлинного тега
    assert options(d, "Ц6", "s52", frozenset({"CH", "BLD", "SB"})) == [F, N]  # версия не подделывается
    assert options(d, "Ц1", "s12", frozenset(PARTICIPANTS)) == [N]           # в D1 нет якоря рецензента
    assert options(DEPLOYMENTS["D3"], "Ц1", "s12", frozenset({"BLD", "REV"})) == [N, P]


def test_best_record_matches_brute_force_on_small_sets():
    """Лучшая запись даёт тот же лучший исход, что полный перебор действий (наборы с перебором до 3^8)."""
    checked = 0
    for d_code in ("D1", "D3"):
        d, rs = DEPLOYMENTS[d_code], RULESETS[d_code]
        for g in GOALS:
            for U in compromise_sets(d, "separate", g):
                C = members(d, "separate", U)
                opts = [options(d, g, e, C) for e in EVIDENCE]
                size = 1
                for o in opts:
                    size *= len(o)
                if size > 3 ** 8:
                    continue
                best = rs.all(best_record(d, g, C))
                for r in rs.CODES:
                    can_admit = can_reach = False
                    for combo in itertools.product(*opts):
                        x = rs.decide(r, dict(zip(EVIDENCE, combo)))
                        can_admit |= x == ADMIT
                        can_reach |= x in (ADMIT, REVIEW)
                    assert can_admit == (best[r] == ADMIT), (d_code, g, sorted(C), r)
                    assert can_reach == (best[r] in (ADMIT, REVIEW)), (d_code, g, sorted(C), r)
                checked += 1
                if checked >= 120:
                    return
    assert checked > 50
