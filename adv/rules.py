# -*- coding: utf-8 -*-
"""Сравниваемые правила допуска П1–П11 (протокол, разд. 4).

Все правила получают одни и те же состояния 17 свидетельств и различаются только агрегацией.
Правила П5, П8–П11 повторяют определения статьи ВАК-2 (пакет scii-gate paper/evidence-graph-method),
П5, П10 и П11 вызывают функции ядра гейта scii/model.py на закреплённом коммите scii-gate.
"""
from __future__ import annotations

import math
import os
import sys
from fractions import Fraction
from typing import Callable, Dict

from .semantics import EVIDENCE, DEPLOYMENTS, Deployment, F, N, P

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCII_GATE = os.environ.get("SCII_GATE") or os.path.join(os.path.dirname(ROOT), "scii-gate")
if SCII_GATE not in sys.path:
    sys.path.insert(0, SCII_GATE)

from scii import __version__ as SCII_VERSION  # noqa: E402  (используется в adv.analysis)
from scii.model import (ADMIT, BOTTOM, BOX, NEIGHBORHOOD, REJECT, REQUEST, REVIEW, THETA_TOL,  # noqa: E402
                        Profile, binary, decide, gate, interval, interval_box)

PROFILE_PATH = os.path.join(SCII_GATE, "profiles", "ardupilot_cubeorange.json")
PROFILE = Profile.load(PROFILE_PATH)
assert list(PROFILE.evidence) == EVIDENCE, "порядок свидетельств профиля изменился"

DECISIONS = [ADMIT, REVIEW, REQUEST, REJECT]
LETTER = {ADMIT: "Д", REVIEW: "Р", REQUEST: "З", REJECT: "О"}


def floor3(x):
    """Округление вниз до 0,001 (процедура назначения порога ВАК-2, как в scii_repro.floor3)."""
    if isinstance(x, Fraction):
        return Fraction(math.floor(x * 1000), 1000)
    return math.floor(x * 1000 + 1e-9) / 1000


def additive(st: Dict[str, str]) -> Fraction:
    """Аддитивный индекс ВАК-2: среднее меток l_A(v) по вершинам в рациональной арифметике."""
    tot = Fraction(0)
    for v in PROFILE.order:
        c, e = Fraction(0), 1
        for s in PROFILE.catalog[v]:
            x = st.get(s.id, N)
            if x == P:
                c += Fraction(str(s.alpha))
            elif x == F:
                e = 0
        tot += e * c
    return tot / len(PROFILE.order)


class RuleSet:
    """Правила П1–П11 с порогами, назначенными по эталону развёртывания (разд. 3.5)."""

    CODES = ["П1", "П2", "П3", "П4", "П5", "П6", "П7", "П8", "П9", "П10", "П11"]
    NAMES = {
        "П1": "подпись поставщика",
        "П2": "подпись и защита от отката",
        "П3": "проверка provenance SLSA",
        "П4": "SLSA с контрольной пересборкой",
        "П5": "бинарный контроль",
        "П6": "бинарный контроль с обязательной пересборкой",
        "П7": "строгая схема (все шаги)",
        "П8": "аддитивный индекс",
        "П9": "графовый индекс без блокирующего условия",
        "П10": "SCII, правило (4), N(w)",
        "П11": "SCII, правило (4), B(w)",
    }
    GRADED = {"П8", "П9", "П10", "П11"}      # правила с исходами кроме допуска и отказа

    def __init__(self, d: Deployment):
        self.d = d
        ref = d.reference
        self.ref_P = d.reference_P
        self.theta = floor3(interval(PROFILE, ref)[0])            # П9, П10
        self.theta_box = floor3(interval_box(PROFILE, ref)[0])    # П11
        self.theta_add = floor3(additive(ref))                    # П8
        self.fn: Dict[str, Callable[[Dict[str, str]], str]] = {c: getattr(self, "r" + c[1:]) for c in self.CODES}

    def thresholds(self) -> Dict[str, str]:
        return {"П8": str(self.theta_add), "П9": "%.3f" % self.theta, "П10": "%.3f" % self.theta,
                "П11": "%.3f" % self.theta_box}

    # ---- П1–П4: проверки подписи, версии, provenance и пересборки ----
    @staticmethod
    def _ok(st, *ids) -> bool:
        return all(st.get(e) == P for e in ids)

    def r1(self, st):
        return ADMIT if self._ok(st, "s42", "s51") else REJECT

    def r2(self, st):
        return ADMIT if self._ok(st, "s42", "s51", "s52", "s53") else REJECT

    def r3(self, st):
        return ADMIT if self._ok(st, "s42", "s51", "s52", "s53", "s22") else REJECT

    def r4(self, st):
        return ADMIT if self._ok(st, "s42", "s51", "s52", "s53", "s22", "s24") else REJECT

    # ---- П5, П6: бинарный контроль ВАК-2 ----
    def r5(self, st):
        return ADMIT if binary(PROFILE, st) == 1 else REJECT

    def r6(self, st):
        return ADMIT if binary(PROFILE, st) == 1 and st.get("s24") == P else REJECT

    # ---- П7: строгая схема ----
    def r7(self, st):
        ok = all(st.get(e) == P for e in self.ref_P) and all(st.get(e) != F for e in EVIDENCE)
        return ADMIT if ok else REJECT

    # ---- П8: аддитивный индекс (var_additive ВАК-2) ----
    def r8(self, st):
        g = gate(PROFILE, st)
        if g == BOTTOM:
            return REQUEST
        m = additive(st)
        if g == 0 or m < self.theta_add:
            return REJECT
        if binary(PROFILE, st) == 1 and m >= self.theta_add:
            return ADMIT
        return REVIEW

    # ---- П9: графовый индекс без блокирующего условия (var_graph_nogate ВАК-2) ----
    def r9(self, st):
        rmin, rmax = interval(PROFILE, st)
        if rmax < self.theta - THETA_TOL:
            return REJECT
        if rmin >= self.theta - THETA_TOL:
            return ADMIT
        return REVIEW

    # ---- П10, П11: SCII, правило (4) ----
    def r10(self, st):
        return decide(PROFILE, st, self.theta, uncertainty=NEIGHBORHOOD)

    def r11(self, st):
        return decide(PROFILE, st, self.theta_box, uncertainty=BOX)

    def decide(self, code: str, st: Dict[str, str]) -> str:
        return self.fn[code](st)

    def all(self, st: Dict[str, str]) -> Dict[str, str]:
        return {c: self.fn[c](st) for c in self.CODES}


RULESETS = {k: RuleSet(d) for k, d in DEPLOYMENTS.items()}
__all__ = ["SCII_VERSION", "RuleSet", "RULESETS", "PROFILE", "PROFILE_PATH", "SCII_GATE", "additive", "floor3"]
