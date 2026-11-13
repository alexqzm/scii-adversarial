# -*- coding: utf-8 -*-
"""Испытание реализации гейта на искажённых комплектах (протокол, разд. 8, гипотеза Г8).

Основы: подлинный B1 и три комплекта атак (Ц1 при C = {BLD}, Ц5 при C = {CH}, Ц4 при C = {REPO}), D1.
К каждой основе применяются искажения файлов, записей bundle.json, аттестаций и пакета. Для каждого
искажённого комплекта фиксируются решение, код выхода, время и дайджест восстановленного образа.

  нарушение Г8 — допуск, когда образ, восстановленный гейтом, отличается от подлинного;
  авария      — выход без решения (код не 0, 10, 20, 30);
  зависание   — превышение ограничения 60 с.

    python -m adv.mutate --out results/mutation.json
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import shutil
import subprocess
import time
import zlib
from typing import Callable, List, Tuple

from .emulate import (COSIGN, GoalKit, Lab, Material, PROFILE_PATH, SCII_GATE, _rjson, _sha, acts_for,
                      build_goal, build_pmi)
from .semantics import DEPLOYMENTS, best_record

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIMIT_S = 60
PY = os.environ.get("ADV_GATE_PYTHON") or __import__("sys").executable
DECISION_CODES = {0, 10, 20, 30}


def run_gate(bundle: str, policy: str) -> dict:
    out = os.path.join(os.path.dirname(bundle), os.path.basename(bundle) + ".report.json")
    if os.path.exists(out):
        os.unlink(out)
    cmd = [PY, "-m", "scii", "verify", "--profile", PROFILE_PATH, "--policy", policy, "--bundle", bundle,
           "--json", out, "--quiet"]
    env = dict(os.environ, PYTHONPATH=SCII_GATE, SCII_COSIGN=COSIGN)
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=SCII_GATE, timeout=LIMIT_S)
        code, err = r.returncode, r.stderr
    except subprocess.TimeoutExpired:
        return {"outcome": "зависание", "exit": None, "seconds": LIMIT_S, "decision": None}
    sec = round(time.time() - t0, 2)
    rep = _rjson(out) if os.path.exists(out) else {}
    if code not in DECISION_CODES:
        last = [x for x in (err or "").strip().splitlines() if x.strip()]
        return {"outcome": "авария", "exit": code, "seconds": sec, "decision": None,
                "error": last[-1][:300] if last else ""}
    art = rep.get("artifact") or {}
    return {"outcome": "решение", "exit": code, "seconds": sec, "decision": rep.get("decision"),
            "states": rep.get("states"), "image_sha256": art.get("image_sha256")}


# ---------------- искажения ----------------
def _files(bundle: str) -> List[str]:
    b = _rjson(os.path.join(bundle, "bundle.json"))
    out = {b["artifact"]}
    for ev in b["evidence"].values():
        for v in ev.values():
            if isinstance(v, str):
                out.add(v)
    return sorted(out)


def _entries(bundle: str) -> List[Tuple[str, str]]:
    b = _rjson(os.path.join(bundle, "bundle.json"))
    return sorted((sid, k) for sid, ev in b["evidence"].items() for k, v in ev.items() if isinstance(v, str))


def _edit_bundle_json(d: str, fn: Callable[[dict], None]):
    p = os.path.join(d, "bundle.json")
    b = _rjson(p)
    fn(b)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(b, f, ensure_ascii=False, indent=1)


def mutations(base: str, outside: str) -> List[Tuple[str, Callable[[str], None]]]:
    """Список (имя, функция искажения каталога-копии)."""
    muts: List[Tuple[str, Callable[[str], None]]] = []
    files = _files(base)
    entries = _entries(base)
    attest = [f for f in files if f.endswith(".intoto.json")]
    # ---- файлы ----
    for f in files:
        muts.append(("файл удалён: %s" % f, lambda d, f=f: os.unlink(os.path.join(d, f))))
        muts.append(("файл пуст: %s" % f, lambda d, f=f: open(os.path.join(d, f), "wb").close()))
        def trunc(d, f=f):
            p = os.path.join(d, f)
            data = open(p, "rb").read()
            open(p, "wb").write(data[:len(data) // 2])
        muts.append(("файл усечён: %s" % f, trunc))
        def link_out(d, f=f):
            p = os.path.join(d, f)
            os.unlink(p)
            os.symlink(os.path.join(outside, f) if os.path.exists(os.path.join(outside, f)) else "/etc/hostname", p)
        muts.append(("ссылка на файл вне комплекта: %s" % f, link_out))
    for f in files:
        others = [x for x in files if x != f and os.path.splitext(x)[1] == os.path.splitext(f)[1]]
        if others:
            o = others[0]
            muts.append(("файл заменён файлом %s: %s" % (o, f),
                         lambda d, f=f, o=o: shutil.copy(os.path.join(d, o), os.path.join(d, f))))
    zero_targets = [x for x in files if x == "package/arducopter.apj" or x.endswith(("commit_object", "tag_object"))]
    zero_targets += attest[:1]
    for f in zero_targets:
        def link_zero(d, f=f):
            p = os.path.join(d, f)
            os.unlink(p)
            os.symlink("/dev/zero", p)
        muts.append(("ссылка на /dev/zero: %s" % f, link_zero))
    # ---- записи bundle.json ----
    for sid, k in entries:
        muts.append(("путь с ..: %s.%s" % (sid, k),
                     lambda d, sid=sid, k=k: _edit_bundle_json(d, lambda b: b["evidence"][sid].__setitem__(
                         k, "../" + os.path.basename(outside) + "/" + b["evidence"][sid][k]))))
        muts.append(("абсолютный путь: %s.%s" % (sid, k),
                     lambda d, sid=sid, k=k: _edit_bundle_json(d, lambda b: b["evidence"][sid].__setitem__(
                         k, "/etc/hostname"))))
        for name, val in (("число", 1), ("список", ["x"]), ("объект", {"x": 1})):
            muts.append(("поле %s.%s — %s" % (sid, k, name),
                         lambda d, sid=sid, k=k, val=val: _edit_bundle_json(
                             d, lambda b: b["evidence"][sid].__setitem__(k, val))))
    sids = sorted({s for s, _ in entries})
    for sid in sids[:3]:
        muts.append(("запись %s — строка вместо объекта" % sid,
                     lambda d, sid=sid: _edit_bundle_json(d, lambda b: b["evidence"].__setitem__(sid, "x"))))
    muts.append(("недопустимый JSON bundle.json",
                 lambda d: open(os.path.join(d, "bundle.json"), "a").write("{")))
    def dup_keys(d):
        p = os.path.join(d, "bundle.json")
        s = open(p, encoding="utf-8").read()
        s = s.replace('"evidence": {', '"evidence": {"s24": {"attestation": "build/none.intoto.json"}, ', 1)
        open(p, "w", encoding="utf-8").write(s)
    muts.append(("повтор ключа s24 в bundle.json", dup_keys))
    muts.append(("evidence — список", lambda d: _edit_bundle_json(d, lambda b: b.__setitem__("evidence", []))))
    muts.append(("build_product_name изменён",
                 lambda d: _edit_bundle_json(d, lambda b: b.__setitem__("build_product_name", "other.bin"))))
    muts.append(("artifact указывает на аттестацию",
                 lambda d: _edit_bundle_json(d, lambda b: b.__setitem__("artifact", attest[0] if attest else "x"))))
    muts.append(("artifact вне комплекта",
                 lambda d: _edit_bundle_json(d, lambda b: b.__setitem__("artifact", "/etc/hostname"))))
    # ---- аттестации ----
    for f in attest:
        def ptype(d, f=f):
            p = os.path.join(d, f)
            env = _rjson(p)
            env["payloadType"] = "application/json"
            json.dump(env, open(p, "w"))
        muts.append(("payloadType изменён: %s" % f, ptype))
        def payload(d, f=f):
            p = os.path.join(d, f)
            env = _rjson(p)
            st = json.loads(base64.b64decode(env["payload"]))
            st["predicate"]["_x"] = 1
            env["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
            json.dump(env, open(p, "w"))
        muts.append(("содержимое заявления изменено: %s" % f, payload))
        def b64(d, f=f):
            p = os.path.join(d, f)
            env = _rjson(p)
            env["payload"] = "%%%" + env["payload"]
            json.dump(env, open(p, "w"))
        muts.append(("неверный base64: %s" % f, b64))
        def extra(d, f=f):
            p = os.path.join(d, f)
            env = _rjson(p)
            sig = dict(env["signatures"][0])
            sig["sig"] = base64.b64encode(b"\x00" * 64).decode()
            env["signatures"] = env["signatures"] + [sig]
            json.dump(env, open(p, "w"))
        muts.append(("лишняя подпись в конверте: %s" % f, extra))
        def reorder(d, f=f):
            p = os.path.join(d, f)
            env = _rjson(p)
            sig = dict(env["signatures"][0])
            sig["sig"] = base64.b64encode(b"\x01" * 64).decode()
            env["signatures"] = [sig] + env["signatures"]
            json.dump(env, open(p, "w"))
        muts.append(("поддельная подпись перед подлинной: %s" % f, reorder))
        def other(d, f=f):
            src = os.path.join(outside, f)
            if os.path.exists(src):
                shutil.copy(src, os.path.join(d, f))
        muts.append(("аттестация другого выпуска: %s" % f, other))
    # ---- пакет ----
    apj = "package/arducopter.apj"
    def bomb(d):
        p = os.path.join(d, apj)
        a = json.load(open(p))
        a["image"] = base64.b64encode(zlib.compress(b"\x00" * (1 << 30), 9)).decode()
        open(p, "w").write(json.dumps(a))
    muts.append(("zlib-бомба 1 ГиБ в образе .apj", bomb))
    def board(d):
        p = os.path.join(d, apj)
        a = json.load(open(p))
        a["board_id"] = 9999
        open(p, "w").write(json.dumps(a, indent=4))
    muts.append(("board_id в метаданных .apj вне подписи", board))
    def nodesc(d):
        p = os.path.join(d, apj)
        a = json.load(open(p))
        img = zlib.decompress(base64.b64decode(a["image"]))
        img = img.replace(bytes([0x41, 0xa3, 0xe5, 0xf2, 0x65, 0x69, 0x92, 0x07]), b"\x00" * 8, 1)
        a["image"] = base64.b64encode(zlib.compress(img, 9)).decode()
        open(p, "w").write(json.dumps(a, indent=4))
    muts.append(("образ без дескриптора", nodesc))
    def badimg(d):
        p = os.path.join(d, apj)
        a = json.load(open(p))
        a["image"] = "%%%"
        open(p, "w").write(json.dumps(a))
    muts.append(("поле image не base64", badimg))
    return muts


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adv.mutate")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "mutation.json"))
    ap.add_argument("--work", default=None)
    ap.add_argument("--skip-memory", action="store_true",
                    help="пропустить ссылки на /dev/zero вместо файлов, которые гейт читает целиком (исчерпание памяти)")
    a = ap.parse_args(argv)
    lab, m = Lab(), Material()
    lab.make_keys()
    lab.make_policies()
    kit = GoalKit(lab, m)
    root = a.work or os.path.join(lab.work, "mutation")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    pmi = build_pmi(lab, m, os.path.join(root, "pmi"))
    bases = {"B1": pmi["B1"]}
    d = DEPLOYMENTS["D1"]
    for goal, C in (("Ц1", {"BLD"}), ("Ц5", {"CH"}), ("Ц4", {"REPO"})):
        C = frozenset(C)
        rec = best_record(d, goal, C)
        bases["%s_%s" % (goal, "_".join(sorted(C)))] = build_goal(kit, "D1", goal, rec, acts_for("D1", goal, rec, C),
                                                                  os.path.join(root, "base", goal))
    genuine = _sha(m.image("B1"))
    policy = lab.policy("policy-D1.json")
    rows = []
    t0 = time.time()
    for bname, base in bases.items():
        ref = run_gate(base, policy)
        outside = pmi["B1"] if bname != "B1" else pmi["A1b"]
        for i, (name, fn) in enumerate(mutations(base, outside)):
            if a.skip_memory and name.startswith("ссылка на /dev/zero") and not name.endswith("arducopter.apj"):
                continue
            dst = os.path.join(root, "m", "%s_%03d" % (bname, i))
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(base, dst, symlinks=True)
            try:
                fn(dst)
            except Exception as e:          # искажение неприменимо к этой основе
                rows.append({"base": bname, "mutation": name, "outcome": "неприменимо", "note": str(e)[:200]})
                shutil.rmtree(dst, ignore_errors=True)
                continue
            r = run_gate(dst, policy)
            r.update({"base": bname, "mutation": name, "base_decision": ref.get("decision")})
            r["violation_g8"] = (r.get("decision") == "допуск" and r.get("image_sha256") != genuine)
            rows.append(r)
            shutil.rmtree(dst, ignore_errors=True)
    summary = {}
    for r in rows:
        s = summary.setdefault(r["base"], {"мутаций": 0, "решение": 0, "авария": 0, "зависание": 0,
                                            "неприменимо": 0, "допуск": 0, "нарушений_Г8": 0})
        s["мутаций"] += 1
        s[r["outcome"]] += 1
        s["допуск"] += r.get("decision") == "допуск"
        s["нарушений_Г8"] += bool(r.get("violation_g8"))
    res = {"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "limit_s": LIMIT_S,
           "genuine_image_sha256": genuine, "summary": summary, "rows": rows,
           "seconds": round(time.time() - t0, 1)}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    for b, s in summary.items():
        print(b, s)
    return 1 if any(s["нарушений_Г8"] for s in summary.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
