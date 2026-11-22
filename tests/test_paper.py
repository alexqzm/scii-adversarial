# -*- coding: utf-8 -*-
"""Скрипты статьи (paper/) запускаются так, как написано в README."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAPER = os.path.join(ROOT, "paper")


def _scripts():
    for folder, _, names in os.walk(PAPER):
        for name in names:
            if name.endswith(".py"):
                yield os.path.join(folder, name)


def _run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=600)


def test_script_names_do_not_shadow_stdlib():
    # При запуске `python paper/vak6/X.py` каталог скрипта стоит первым в sys.path. Файл с именем
    # стандартного модуля подменяет его для всех скриптов каталога: numbers.py ломал импорт numpy в fig1.py.
    clash = sorted(os.path.relpath(p, ROOT) for p in _scripts()
                   if os.path.splitext(os.path.basename(p))[0] in sys.stdlib_module_names)
    assert clash == []


def test_article_numbers_runs():
    r = _run(os.path.join("paper", "vak6", "article_numbers.py"), "--json")
    assert r.returncode == 0, r.stderr
    numbers = json.loads(r.stdout)
    assert numbers["hypotheses"] and numbers["k_admit_D1"]


def test_fig1_runs(tmp_path):
    pytest.importorskip("matplotlib")  # ставится отдельно, paper/vak6/requirements.txt
    base = str(tmp_path / "fig1")
    r = _run(os.path.join("paper", "vak6", "fig1.py"), base)
    assert r.returncode == 0, r.stderr
    for ext in ("png", "tif", "jpg"):
        assert os.path.getsize("%s.%s" % (base, ext)) > 0
