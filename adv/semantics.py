# -*- coding: utf-8 -*-
"""Модель нарушителя по протоколу (docs/PROTOCOL.md, разд. 3): участники, цели, честные состояния,
развёртывания, действия нарушителя и лучшая запись.

Все таблицы этого модуля переписаны из протокола 1.0 и проверяются тестом tests/test_semantics.py.
Состояния свидетельств: P (подтверждено), N (отсутствует), F (опровергнуто).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Tuple

P, N, F = "P", "N", "F"
RANK = {F: 0, N: 1, P: 2}                       # порядок F < N < P

EVIDENCE = ["s11", "s12", "s13", "s14", "s21", "s22", "s23", "s24", "s31", "s32", "s41", "s42", "s43",
            "s51", "s52", "s53", "s54"]

# ---------------- участники (протокол, табл. 3.1) ----------------
PARTICIPANTS = ["ARC", "DEP", "TAG", "SAST", "TEST", "BLD", "IND", "REPO", "PKG", "SB", "CH", "REV"]
PARTICIPANT_NAME = {
    "ARC": "публикация архива исходников выпуска",
    "DEP": "репозиторий зависимости",
    "TAG": "ключ поставщика для подписи тегов",
    "SAST": "служба статического анализа",
    "TEST": "служба испытаний",
    "BLD": "сборочный агент",
    "IND": "независимый исполнитель контрольной пересборки",
    "REPO": "хранилище артефактов",
    "PKG": "ключ поставщика для подписи пакета",
    "SB": "ключ поставщика для защищённой загрузки",
    "CH": "канал доставки комплекта гейту",
    "REV": "рецензент",
}
INTRUDER_TYPE = {"ARC": "Н2", "DEP": "Н2", "TAG": "Н2", "SAST": "Н3", "TEST": "Н3", "BLD": "Н3", "IND": "Н3",
                 "REPO": "Н3", "PKG": "Н2", "SB": "Н2", "CH": "Н4", "REV": "Н2"}

#: кто формирует свидетельство; у s11, s52, s53, s54 формирующего участника нет
PRODUCER = {"s12": "REV", "s13": "SAST", "s14": "TAG", "s21": "BLD", "s22": "BLD", "s23": "BLD", "s24": "IND",
            "s31": "REPO", "s32": "REPO", "s41": "BLD", "s42": "PKG", "s43": "TEST", "s51": "SB"}

#: повтор свидетельства текущего подлинного выпуска (разд. 3.4): привязанные к коммиту дают P, s11 — N
#: (объект коммита апстрима не подписан); привязанные к образу или пакету — F (субъект не совпадает)
REPLAY = {"s11": N, "s13": P, "s14": P, "s43": P}

# ---------------- цели (табл. 3.2) и честные состояния (табл. 3.3) ----------------
GOALS = ["Ц1", "Ц2", "Ц3", "Ц4", "Ц5", "Ц6"]
GOAL = {
    "Ц1": {"name": "внедрение на сборочном агенте", "threat": "У5", "entry": "BLD", "basis": "A5a"},
    "Ц2": {"name": "сборка из архива, отличного от git", "threat": "У6", "entry": "ARC", "basis": "A3"},
    "Ц3": {"name": "подмена зависимости", "threat": "У3", "entry": "DEP", "basis": "A7"},
    "Ц4": {"name": "подмена образа в хранилище до подписи пакета", "threat": "У8", "entry": "REPO", "basis": None},
    "Ц5": {"name": "подмена пакета в канале после подписи", "threat": "У8", "entry": "CH", "basis": "A1a"},
    "Ц6": {"name": "откат на подлинный предыдущий выпуск", "threat": "У9", "entry": "CH", "basis": "A4"},
}
#: строки в порядке EVIDENCE: s11 s12 s13 s14 s21 s22 s23 s24 s31 s32 s41 s42 s43 s51 s52 s53 s54
_HONEST_ROWS = {
    "Ц1": "N N P P F F F F P P F P P P P P N",
    "Ц2": "N N P P F F F F P P P P P P P P N",
    "Ц3": "N N P P P P P F P P F P P P P P N",
    "Ц4": "N N P P F F F F F P F P P P P P N",
    "Ц5": "N N P P F F F F F P F F P F P P N",
    "Ц6": "F N N F F F N N P P F P N P F P N",
}
HONEST: Dict[str, Dict[str, str]] = {g: dict(zip(EVIDENCE, row.split())) for g, row in _HONEST_ROWS.items()}


# ---------------- развёртывания (табл. 3.5) ----------------
@dataclass(frozen=True)
class Deployment:
    code: str
    name: str
    participants: Tuple[str, ...]          # участники, которых можно скомпрометировать
    anchors: FrozenSet[str]                # свидетельства с якорем доверия в политике
    reference: Dict[str, str] = field(compare=False, hash=False)   # эталон: состояния 17 свидетельств

    @property
    def reference_P(self) -> List[str]:
        return [e for e in EVIDENCE if self.reference[e] == P]

    @property
    def supplied(self) -> List[str]:
        """Предоставляемые поставщиком свидетельства эталона (разд. 5.6): без s52 и s53, которые гейт
        вычисляет по образу."""
        return [e for e in self.reference_P if e not in ("s52", "s53")]


def _ref(absent: Iterable[str]) -> Dict[str, str]:
    st = {e: P for e in EVIDENCE}
    for e in absent:
        st[e] = N
    return st


_ANCHORS_D1 = frozenset(EVIDENCE) - {"s11", "s12", "s54"}
DEPLOYMENTS = {
    "D1": Deployment("D1", "стенд (эталон B1)",
                     tuple(p for p in PARTICIPANTS if p != "REV"), _ANCHORS_D1,
                     _ref(["s11", "s12", "s54"])),
    "D2": Deployment("D2", "без независимой пересборки (эталон B3)",
                     tuple(p for p in PARTICIPANTS if p not in ("REV", "IND")), _ANCHORS_D1 - {"s24"},
                     _ref(["s11", "s12", "s54", "s24"])),
    "D3": Deployment("D3", "якорь рецензента без рецензирования (эталон B1)",
                     tuple(PARTICIPANTS), _ANCHORS_D1 | {"s12"},
                     _ref(["s11", "s12", "s54"])),
}
#: свидетельства, которые честная цепочка формирует и предъявляет в развёртывании
PRODUCED_BY_HONEST_CHAIN = {
    "D1": frozenset(_ANCHORS_D1),
    "D2": frozenset(_ANCHORS_D1 - {"s24"}),
    "D3": frozenset(_ANCHORS_D1),               # s12 в D3 имеет якорь, но честная цепочка его не предъявляет
}


def honest_state(d: Deployment, goal: str, e: str) -> str:
    """Честное состояние (табл. 3.3) с поправкой на развёртывание: свидетельство, которое честная цепочка
    не формирует (s24 в D2, s12 в D3, s11/s12/s54 везде), не предъявляется и имеет состояние N.
    Исключение: s11 в цели Ц6 — объект коммита предыдущего выпуска предъявляется и опровергается (F)."""
    if goal == "Ц6" and e == "s11":
        return F
    if e not in PRODUCED_BY_HONEST_CHAIN[d.code]:
        return N
    return HONEST[goal][e]


# ---------------- группировка участников (разд. 3.1) ----------------
GROUPINGS = {
    "separate": None,
    "org": {"REL": ("TAG", "PKG", "SB", "CH"), "CI": ("BLD", "SAST", "TEST")},
}


def units(d: Deployment, grouping: str) -> Dict[str, Tuple[str, ...]]:
    """Единицы компрометации: имя -> участники. Для «separate» каждый участник отдельно."""
    groups = GROUPINGS[grouping] or {}
    out: Dict[str, Tuple[str, ...]] = {}
    covered = set()
    for g, members in groups.items():
        m = tuple(p for p in members if p in d.participants)
        if m:
            out[g] = m
            covered |= set(m)
    for p in d.participants:
        if p not in covered:
            out[p] = (p,)
    return out


def entry_unit(d: Deployment, grouping: str, goal: str) -> str:
    entry = GOAL[goal]["entry"]
    for u, members in units(d, grouping).items():
        if entry in members:
            return u
    raise KeyError(entry)


# ---------------- действия нарушителя и лучшая запись (разд. 3.4) ----------------
def options(d: Deployment, goal: str, e: str, C: FrozenSet[str]) -> List[str]:
    """Достижимые состояния свидетельства e при наборе участников C (множество участников, не единиц)."""
    opts = {honest_state(d, goal, e)}
    prod = PRODUCER.get(e)
    if prod is not None and prod in C and e in d.anchors:
        opts.add(P)                                 # подделка ключом участника
    if "CH" in C:
        opts.add(N)                                 # сокрытие (в том числе s51–s53, см. разд. 3.4)
        if e in REPLAY:
            opts.add(REPLAY[e])                     # повтор свидетельства текущего подлинного выпуска
    return sorted(opts, key=RANK.get)


def best_record(d: Deployment, goal: str, C: FrozenSet[str]) -> Dict[str, str]:
    """Наибольшая достижимая запись: в каждом свидетельстве наибольшее достижимое состояние."""
    return {e: options(d, goal, e, C)[-1] for e in EVIDENCE}


def action_for(d: Deployment, goal: str, e: str, C: FrozenSet[str], state: str) -> str:
    """Действие нарушителя, дающее состояние state (для сборки комплекта эмуляции).
    Порядок выбора: честное, повтор подлинного (не требует ключа), подделка, сокрытие."""
    if state == honest_state(d, goal, e):
        return "honest"
    if "CH" in C and REPLAY.get(e) == state:
        return "replay"
    prod = PRODUCER.get(e)
    if state == P and prod is not None and prod in C and e in d.anchors:
        return "forge"
    if "CH" in C and state == N:
        return "withhold"
    raise ValueError("состояние %s недостижимо для %s/%s/%s при %s" % (state, d.code, goal, e, sorted(C)))


def members(d: Deployment, grouping: str, unit_set: Iterable[str]) -> FrozenSet[str]:
    u = units(d, grouping)
    out = set()
    for x in unit_set:
        out |= set(u[x])
    return frozenset(out)


def compromise_sets(d: Deployment, grouping: str, goal: str):
    """Все наборы единиц компрометации, содержащие единицу с точкой внедрения цели."""
    u = list(units(d, grouping))
    entry = entry_unit(d, grouping, goal)
    rest = [x for x in u if x != entry]
    for k in range(len(rest) + 1):
        for comb in itertools.combinations(rest, k):
            yield frozenset((entry,) + comb)
