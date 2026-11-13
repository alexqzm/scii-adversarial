# -*- coding: utf-8 -*-
"""Эмуляция атак на артефактах стенда ArduPilot (протокол, разд. 2 и 7).

Перевыпуск ключей. Закрытые ключи прогона ПМИ 30.10.2026 не сохранились, поэтому все ключи ролей создаются
заново: cosign (сборщик, независимый пересборщик, поставщик, поставщик после смены ключа, хранилище, SAST,
испытания, рецензент, нарушитель), Monocypher для защищённой загрузки (поставщик, поставщик после смены
ключа, нарушитель) и OpenPGP для тегов (поставщик, нарушитель). Образы и содержимое свидетельств (предикаты
аттестаций, объекты коммита и тега, журналы хранилища) берутся из комплектов scii-gate data/bundles, меняются
только подписи. Образ сборки, к которому привязаны аттестации, при переподписи пакета не меняется: гейт
восстанавливает его, обнуляя поле подписи.

    python -m adv.emulate keys                    ключи и политики D1, D1 (смена ключа), D2, D3
    python -m adv.emulate pmi                     Г0: 16 сценариев ПМИ на перевыпущенном стенде
    python -m adv.emulate goals                   Г7: комплекты лучших записей и одиночных действий
    python -m adv.emulate all                     всё по порядку, итог в results/emulation.json

Окружение: Python 3.11 с pymonocypher 3.1.3.2, cosign v2.4.1 (SCII_COSIGN или в PATH), GnuPG,
scii-gate на закреплённом коммите (SCII_GATE). Рабочий каталог ADV_WORK (по умолчанию work/).
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from typing import Dict, FrozenSet, List, Optional, Tuple

from .rules import PROFILE_PATH, RULESETS, SCII_GATE
from .semantics import (DEPLOYMENTS, EVIDENCE, GOALS, GOAL, P, N, PRODUCER, REPLAY, action_for, best_record,
                        honest_state)

from scii.checks import (DESC_LEN, apj_image, parse_descriptor, unsigned_image)  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.abspath(os.environ.get("ADV_WORK") or os.path.join(ROOT, "work"))
SRC = os.path.join(SCII_GATE, "data", "bundles")
COSIGN = os.environ.get("SCII_COSIGN") or shutil.which("cosign") or "cosign"
PNAME = "arducopter-Copter-4.5.7-CubeOrange.bin"
SIG_HEADER = 30437                      # первые 8 байт поля подписи дескриптора (check_secure_boot)

COSIGN_ROLES = ["builder", "independent_builder", "vendor", "vendor2", "repository", "sast", "tester",
                "reviewer", "attacker"]
SB_ROLES = ["vendor", "vendor2", "attacker"]
GPG_ROLES = ["vendor", "attacker"]
T_REVIEW = "urn:scii:predicate:review:v1"

#: роль ключа (cosign/OpenPGP/Monocypher) участника модели нарушителя
ROLE_OF = {"SAST": "sast", "TEST": "tester", "BLD": "builder", "IND": "independent_builder", "REPO": "repository",
           "PKG": "vendor", "SB": "vendor", "TAG": "vendor", "REV": "reviewer"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rjson(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _wjson(path, obj, indent=1):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=indent)


def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, **kw)
    if r.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(map(str, cmd[:3])), (r.stderr or b"")[-400:]))
    return r


# =====================================================================================================
# Ключи и политики
# =====================================================================================================
class Lab:
    def __init__(self, work: str = WORK):
        self.work = work
        self.priv = os.path.join(work, "keys", "private")
        self.pol = os.path.join(work, "policy")
        self.pub = os.path.join(self.pol, "keys")
        self.gnupg = os.path.join(work, "keys", "gnupg")
        self.tmp = os.path.join(work, "tmp")
        for d in (self.priv, self.pub, self.gnupg, self.tmp):
            os.makedirs(d, exist_ok=True)
        os.chmod(self.gnupg, 0o700)
        self.env = dict(os.environ, COSIGN_PASSWORD="", GNUPGHOME=self.gnupg)

    # ---- создание ----
    def make_keys(self):
        for role in COSIGN_ROLES:
            if not os.path.exists(os.path.join(self.priv, role + ".key")):
                _run([COSIGN, "generate-key-pair", "--output-key-prefix", role], cwd=self.priv, env=self.env)
            shutil.copy(os.path.join(self.priv, role + ".pub"), os.path.join(self.pub, role + ".pub"))
        import monocypher
        for who in SB_ROLES:
            sk_path = os.path.join(self.priv, "secure_boot_%s.key" % who)
            if not os.path.exists(sk_path):
                sk, pk = monocypher.generate_signing_key_pair()
                with open(sk_path, "w") as f:
                    f.write(base64.b64encode(sk).decode() + "\n")
            sk = self.sb_secret(who)
            pk = monocypher.compute_signing_public_key(sk)
            with open(os.path.join(self.pub, "secure_boot_%s.dat" % who), "w") as f:
                f.write("PUBLIC_KEYV1:" + base64.b64encode(pk).decode())
        for who in GPG_ROLES:
            uid = "SCII adversarial %s <%s@scii-adversarial.invalid>" % (who, who)
            r = subprocess.run(["gpg", "--batch", "--list-keys", uid], capture_output=True, env=self.env)
            if r.returncode != 0:
                _run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", uid,
                      "ed25519", "sign", "never"], env=self.env)
        with open(os.path.join(self.pub, "tag_signers.asc"), "wb") as f:
            f.write(_run(["gpg", "--batch", "--armor", "--export", "vendor@scii-adversarial.invalid"],
                         env=self.env).stdout)

    def fpr(self, who: str) -> str:
        out = _run(["gpg", "--batch", "--with-colons", "--list-keys", "%s@scii-adversarial.invalid" % who],
                   env=self.env).stdout.decode()
        for ln in out.splitlines():
            if ln.startswith("fpr:"):
                return ln.split(":")[9]
        raise RuntimeError("нет отпечатка ключа %s" % who)

    def sb_secret(self, who: str) -> bytes:
        with open(os.path.join(self.priv, "secure_boot_%s.key" % who)) as f:
            return base64.b64decode(f.read().strip())

    def make_policies(self):
        """Политики получателя: ожидания стенда scii-gate, новые якоря доверия."""
        base = _rjson(os.path.join(SCII_GATE, "testbed", "policy", "policy.json"))
        keys = {"builder": "keys/builder.pub", "independent_builder": "keys/independent_builder.pub",
                "vendor": ["keys/vendor.pub"], "repository": "keys/repository.pub", "sast": "keys/sast.pub",
                "tester": "keys/tester.pub", "tag_signers": "keys/tag_signers.asc",
                "secure_boot": ["keys/secure_boot_vendor.dat"]}
        expect = copy.deepcopy(base["expect"])
        expect["tag_signer_fingerprints"] = [self.fpr("vendor")]
        def write(name, k, comment):
            _wjson(os.path.join(self.pol, name), {"name": "Политика получателя scii-adversarial: " + comment,
                                                  "comment": "Ожидания как в testbed/policy/policy.json scii-gate "
                                                             "d210811, якоря доверия перевыпущены.",
                                                  "keys": k, "expect": expect})
        write("policy-D1.json", keys, "D1, стенд")
        rot = copy.deepcopy(keys)
        rot["vendor"] = ["keys/vendor.pub", "keys/vendor2.pub"]
        rot["secure_boot"] = ["keys/secure_boot_vendor.dat", "keys/secure_boot_vendor2.dat"]
        write("policy-D1-rotated.json", rot, "D1, политика обновлена после смены ключа поставщика")
        d2 = {k: v for k, v in keys.items() if k != "independent_builder"}
        write("policy-D2.json", d2, "D2, без независимой пересборки")
        d3 = dict(keys, reviewer="keys/reviewer.pub")
        write("policy-D3.json", d3, "D3, якорь рецензента")

    def policy(self, name: str) -> str:
        return os.path.join(self.pol, name)

    # ---- подписи ----
    def attest(self, role: str, ptype: str, predicate: dict, blob: bytes, out: str):
        os.makedirs(os.path.dirname(out), exist_ok=True)
        fd, pf = tempfile.mkstemp(dir=self.tmp, suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(predicate, f, ensure_ascii=False)
        fd, bf = tempfile.mkstemp(dir=self.tmp, suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        try:
            _run([COSIGN, "attest-blob", "--key", os.path.join(self.priv, role + ".key"), "--predicate", pf,
                  "--type", ptype, "--tlog-upload=false", "--yes", "--output-signature", out, bf], env=self.env)
        finally:
            os.unlink(pf)
            os.unlink(bf)

    def sign_blob(self, role: str, blob_path: str, out: str):
        _run([COSIGN, "sign-blob", "--key", os.path.join(self.priv, role + ".key"), "--tlog-upload=false", "--yes",
              "--bundle", out, blob_path], env=self.env)

    def sign_tag(self, who: str, payload: str) -> bytes:
        r = _run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--detach-sign",
                  "--local-user", "%s@scii-adversarial.invalid" % who], input=payload.encode(), env=self.env)
        return payload.encode() + r.stdout

    def sb_sign(self, who: str, img_unsigned: bytes) -> bytes:
        """Подпись образа для защищённой загрузки так, как её проверяет гейт (check_secure_boot)."""
        import monocypher
        desc = parse_descriptor(img_unsigned)
        o, size = desc["offset"], desc["image_size"]
        msg = img_unsigned[:o] + img_unsigned[o + DESC_LEN:size]
        sig = monocypher.signature_sign(self.sb_secret(who), msg)
        field = struct.pack("<I", 72) + struct.pack("<Q", SIG_HEADER) + sig
        assert len(field) == 76
        return img_unsigned[:o + 16] + field + img_unsigned[o + DESC_LEN:]


# =====================================================================================================
# Материал из комплектов прогона ПМИ
# =====================================================================================================
class Material:
    def __init__(self, src: str = SRC):
        self.src = src
        self.bundle = {b: _rjson(os.path.join(src, b, "bundle.json")) for b in sorted(os.listdir(src))}
        self._img: Dict[str, bytes] = {}

    def path(self, b: str, rel: str) -> str:
        return os.path.join(self.src, b, rel)

    def read(self, b: str, rel: str) -> bytes:
        with open(self.path(b, rel), "rb") as f:
            return f.read()

    def statement(self, b: str, eid: str) -> dict:
        env = _rjson(self.path(b, self.bundle[b]["evidence"][eid]["attestation"]))
        return json.loads(base64.b64decode(env["payload"]))

    def apj(self, b: str) -> dict:
        return _rjson(self.path(b, "package/arducopter.apj"))

    def signed_image(self, b: str) -> bytes:
        return apj_image(self.path(b, "package/arducopter.apj"))[1]

    def image(self, b: str) -> bytes:
        """Образ сборки, восстановленный из пакета (поле подписи обнулено)."""
        if b not in self._img:
            self._img[b] = unsigned_image(self.signed_image(b))
        return self._img[b]

    def tag_payload(self, b: str) -> str:
        raw = self.read(b, "source/tag_object").decode()
        return raw[:raw.index("-----BEGIN PGP SIGNATURE-----")]

    def log(self, b: str) -> List[dict]:
        return [json.loads(x) for x in self.read(b, "repository/log.jsonl").decode().splitlines() if x.strip()]


def write_apj(template: dict, img: bytes, out: str):
    d = dict(template)
    d["image"] = base64.b64encode(zlib.compress(img, 9)).decode()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write(json.dumps(d, indent=4))


def tamper_after_signing(signed_img: bytes) -> bytes:
    """A1a: байты строки образа изменены после подписи, контрольные суммы и подпись не пересчитаны."""
    off = signed_img.find(b"load_all took")
    assert off > 0
    return signed_img[:off] + b"LOAD_ALL took" + signed_img[off + 13:]


# =====================================================================================================
# Сборка комплекта
# =====================================================================================================
class Bundle:
    def __init__(self, lab: Lab, dst: str, product_name: str = PNAME):
        self.lab, self.dst = lab, dst
        shutil.rmtree(dst, ignore_errors=True)
        os.makedirs(dst)
        self.ev: Dict[str, dict] = {}
        self.product_name = product_name
        self.meta: Dict[str, object] = {}

    def p(self, rel: str) -> str:
        return os.path.join(self.dst, rel)

    def put(self, rel: str, data: bytes):
        os.makedirs(os.path.dirname(self.p(rel)), exist_ok=True)
        with open(self.p(rel), "wb") as f:
            f.write(data)

    def finish(self):
        _wjson(self.p("bundle.json"), {"artifact": "package/arducopter.apj", "build_product_name": self.product_name,
                                        "evidence": self.ev, "meta": self.meta})


# =====================================================================================================
# Г0: 16 сценариев ПМИ на перевыпущенном стенде
# =====================================================================================================
def _resign_source(bd: Bundle, m: Material, b: str, ids, sast_role="sast", tester_role="tester", tag_who="vendor"):
    ev = m.bundle[b]["evidence"]
    if "s11" in ids and "s11" in ev:
        bd.put("source/commit_object", m.read(b, "source/commit_object"))
        bd.ev["s11"] = {"commit_object": "source/commit_object"}
    if "s14" in ids and "s14" in ev:
        bd.put("source/tag_object", bd.lab.sign_tag(tag_who, m.tag_payload(b)))
        bd.ev["s14"] = {"tag_object": "source/tag_object"}
    for sid, role, name in (("s13", sast_role, "sast"), ("s43", tester_role, "tests")):
        if sid in ids and sid in ev:
            ct = m.read(b, "source/commit.txt")
            bd.put("source/commit.txt", ct)
            st = m.statement(b, sid)
            assert st["subject"][0]["digest"]["sha256"] == _sha(ct)
            bd.lab.attest(role, st["predicateType"], st["predicate"], ct, bd.p("source/%s.intoto.json" % name))
            bd.ev[sid] = {"subject": "source/commit.txt", "attestation": "source/%s.intoto.json" % name}


IMAGE_OF = {}   # дайджест образа -> имя комплекта, из пакета которого он восстанавливается


def _image_by_digest(m: Material, digest: str) -> bytes:
    if not IMAGE_OF:
        for b in m.bundle:
            IMAGE_OF.setdefault(_sha(m.image(b)), b)
    return m.image(IMAGE_OF[digest])


def _resign_build(bd: Bundle, m: Material, b: str, ids, builder_role="builder", ind_role="independent_builder"):
    ev = m.bundle[b]["evidence"]
    names = {"s21": "link", "s22": "provenance", "s23": "repro", "s41": "sbom", "s24": "rebuild-independent"}
    for sid in ("s21", "s22", "s23", "s41", "s24"):
        if sid in ids and sid in ev:
            st = m.statement(b, sid)
            blob = _image_by_digest(m, st["subject"][0]["digest"]["sha256"])
            rel = "build/%s.intoto.json" % names[sid]
            bd.lab.attest(ind_role if sid == "s24" else builder_role, st["predicateType"], st["predicate"], blob,
                          bd.p(rel))
            bd.ev[sid] = {"attestation": rel}


def _resign_repo(bd: Bundle, m: Material, b: str, ids, role="repository"):
    ev = m.bundle[b]["evidence"]
    if any(s in ids and s in ev for s in ("s31", "s32")):
        bd.put("repository/log.jsonl", m.read(b, "repository/log.jsonl"))
        bd.lab.sign_blob(role, bd.p("repository/log.jsonl"), bd.p("repository/log.sigstore.json"))
        for s in ("s31", "s32"):
            if s in ids and s in ev:
                bd.ev[s] = {"log": "repository/log.jsonl", "signature": "repository/log.sigstore.json"}


def _package(bd: Bundle, m: Material, b: str, sb_who: Optional[str], pkg_role: Optional[str], ids):
    """Пакет комплекта b: образ переподписан ключом защищённой загрузки sb_who (None — пакет как есть),
    подпись пакета cosign ролью pkg_role (None — без s42)."""
    apj_path = bd.p("package/arducopter.apj")
    if sb_who is None:
        os.makedirs(os.path.dirname(apj_path), exist_ok=True)
        shutil.copy(m.path(b, "package/arducopter.apj"), apj_path)
    else:
        write_apj(m.apj(b), bd.lab.sb_sign(sb_who, m.image(b)), apj_path)
    if pkg_role and "s42" in ids:
        bd.lab.sign_blob(pkg_role, apj_path, apj_path + ".sigstore.json")
        bd.ev["s42"] = {"signature": "package/arducopter.apj.sigstore.json"}
    for s in ("s51", "s52", "s53"):
        if s in ids:
            bd.ev[s] = {"embedded": True}


PMI_POLICY = {"B5b": "policy-D1-rotated.json"}


def build_pmi(lab: Lab, m: Material, out: str) -> Dict[str, str]:
    """Комплекты 16 сценариев ПМИ с новыми ключами. Состав свидетельств каждого комплекта тот же, что в исходном."""
    dirs = {}
    for b in m.bundle:
        ids = set(m.bundle[b]["evidence"])
        bd = Bundle(lab, os.path.join(out, b), m.bundle[b].get("build_product_name", PNAME))
        bd.meta = {"pmi": b, "source_bundle": "scii-gate d210811 data/bundles/%s" % b}
        if b == "A1b":                              # всё подписано ключами нарушителя
            _resign_source(bd, m, b, ids, sast_role="attacker", tester_role="attacker", tag_who="attacker")
            _resign_build(bd, m, b, ids, builder_role="attacker", ind_role="attacker")
            _resign_repo(bd, m, b, ids, role="attacker")
            _package(bd, m, b, "attacker", "attacker", ids)
        elif b == "A1a":                            # пакет B1 изменён после подписи
            _resign_source(bd, m, b, ids)
            _resign_build(bd, m, b, ids)
            _resign_repo(bd, m, b, ids)
            write_apj(m.apj("B1"), lab.sb_sign("vendor", m.image("B1")), bd.p("package/genuine.apj"))
            lab.sign_blob("vendor", bd.p("package/genuine.apj"), bd.p("package/arducopter.apj.sigstore.json"))
            signed = apj_image(bd.p("package/genuine.apj"))[1]
            write_apj(m.apj("B1"), tamper_after_signing(signed), bd.p("package/arducopter.apj"))
            os.unlink(bd.p("package/genuine.apj"))
            bd.ev["s42"] = {"signature": "package/arducopter.apj.sigstore.json"}
            for s in ("s51", "s52", "s53"):
                bd.ev[s] = {"embedded": True}
        elif b in ("O1", "O2"):                     # официальный пакет апстрима без подписей
            _resign_source(bd, m, b, ids)
            _resign_build(bd, m, b, ids)
            _package(bd, m, b, None, None, ids)
        else:
            tag_who = "attacker" if b == "A6" else "vendor"
            if b == "A6":                           # тег из A1b, подписанный ключом нарушителя
                _resign_source(bd, m, "B1", ids - {"s14"})
                bd.put("source/tag_object", lab.sign_tag("attacker", m.tag_payload("A1b")))
                bd.ev["s14"] = {"tag_object": "source/tag_object"}
            else:
                _resign_source(bd, m, b, ids, tag_who=tag_who)
            _resign_build(bd, m, b, ids)
            _resign_repo(bd, m, b, ids)
            who = "vendor2" if b.startswith("B5") else "vendor"
            _package(bd, m, b, who, who, ids)
        bd.finish()
        dirs[b] = bd.dst
    return dirs


# =====================================================================================================
# Г7: комплекты действий нарушителя по целям
# =====================================================================================================
GOAL_IMAGE = {"Ц1": "A5a", "Ц2": "A3", "Ц3": "A7", "Ц6": "A4"}


class GoalKit:
    """Свидетельства для цели: честные, подделанные, повтор подлинного. Кэш файлов по (цель, вариант образа)."""

    def __init__(self, lab: Lab, m: Material):
        self.lab, self.m = lab, m
        self.genuine = m.image("B1")
        self.genuine_digest = _sha(self.genuine)
        self.commit_txt = m.read("B1", "source/commit.txt")

    # ---- пакет цели ----
    def package(self, bd: Bundle, goal: str, rec: Dict[str, str], acts: Dict[str, str]) -> bytes:
        """Пишет package/arducopter.apj и возвращает образ сборки (без подписи) для привязки свидетельств."""
        apj = bd.p("package/arducopter.apj")
        lab, m = self.lab, self.m
        if goal in GOAL_IMAGE:                          # честный поставщик подписывает то, что получил
            b = GOAL_IMAGE[goal]
            img = m.image(b)
            write_apj(m.apj(b), lab.sb_sign("vendor", img), apj)
            bd.product_name = m.bundle[b].get("build_product_name", PNAME)
        elif goal == "Ц4":                              # образ из хранилища с пересчитанными CRC (как A1b)
            img = m.image("A1b")
            write_apj(m.apj("B1"), lab.sb_sign("vendor", img), apj)
        elif goal == "Ц5":
            if acts.get("s51") == "forge":              # нарушитель с ключом SB пересчитывает CRC и подписывает
                img = m.image("A1b")
                write_apj(m.apj("B1"), lab.sb_sign("vendor", img), apj)
            else:                                       # изменение после подписи (A1a)
                signed = lab.sb_sign("vendor", self.genuine)
                tampered = tamper_after_signing(signed)
                write_apj(m.apj("B1"), tampered, apj)
                img = unsigned_image(tampered)
        else:
            raise KeyError(goal)
        return img

    def genuine_package_signature(self, bd: Bundle):
        """Подпись поставщика над подлинным пакетом (для честного s42 в Ц5)."""
        tmp = bd.p("package/genuine.apj")
        write_apj(self.m.apj("B1"), self.lab.sb_sign("vendor", self.genuine), tmp)
        self.lab.sign_blob("vendor", tmp, bd.p("package/arducopter.apj.sigstore.json"))
        os.unlink(tmp)

    # ---- предикаты ----
    def pred(self, b: str, sid: str) -> Tuple[str, dict]:
        st = self.m.statement(b, sid)
        return st["predicateType"], copy.deepcopy(st["predicate"])

    def repro_pred(self, digest: str, commit: Optional[str]) -> Tuple[str, dict]:
        ptype, p = self.pred("B1", "s23")
        p["source"]["commit"] = commit
        p["builds"] = [{"run": "r1", "sha256": digest}, {"run": "r2", "sha256": digest}]
        p["candidate"] = {"sha256": digest}
        p["rebuilt"] = {"sha256": digest}
        p["result"] = "MATCH"
        return ptype, p

    def rebuild_pred(self, candidate: str, rebuilt: str) -> Tuple[str, dict]:
        ptype, p = self.pred("B1", "s24")
        p["candidate"] = {"sha256": candidate}
        p["rebuilt"] = {"sha256": rebuilt}
        p["result"] = "MATCH" if candidate == rebuilt else "MISMATCH"
        return ptype, p


EXPECTED_COMMIT = "2a3dc4b7bf2507120f7378a7b2fde73185e0c325"
NAMES = {"s21": "link", "s22": "provenance", "s23": "repro", "s41": "sbom", "s24": "rebuild-independent"}


def build_goal(kit: GoalKit, d_code: str, goal: str, rec: Dict[str, str], acts: Dict[str, str], dst: str) -> str:
    """Комплект цели goal: состояния rec, действия acts (honest/forge/withhold/replay) по свидетельствам."""
    lab, m = kit.lab, kit.m
    bd = Bundle(lab, dst)
    bd.meta = {"deployment": d_code, "goal": goal, "record": "".join(rec[e] for e in EVIDENCE), "actions": acts}
    img = kit.package(bd, goal, rec, acts)
    dig = _sha(img)
    # ---- исходный код ----
    a = acts["s11"]
    if a != "withhold":
        src = "A4" if (goal == "Ц6" and a == "honest") else "B1"
        bd.put("source/commit_object", m.read(src, "source/commit_object"))
        bd.ev["s11"] = {"commit_object": "source/commit_object"}
    a = acts["s14"]
    if a != "withhold" and not (a == "honest" and rec["s14"] == N):
        payload = m.tag_payload("A4" if (goal == "Ц6" and a == "honest") else "B1")
        bd.put("source/tag_object", lab.sign_tag("vendor", payload))
        bd.ev["s14"] = {"tag_object": "source/tag_object"}
    for sid, role, name in (("s13", "sast", "sast"), ("s43", "tester", "tests")):
        a = acts[sid]
        if a in ("honest", "forge", "replay") and not (a == "honest" and rec[sid] == N):
            bd.put("source/commit.txt", kit.commit_txt)
            ptype, pr = kit.pred("B1", sid)
            lab.attest(role, ptype, pr, kit.commit_txt, bd.p("source/%s.intoto.json" % name))
            bd.ev[sid] = {"subject": "source/commit.txt", "attestation": "source/%s.intoto.json" % name}
    if acts["s12"] == "forge":
        bd.put("source/commit.txt", kit.commit_txt)
        pr = {"result": "APPROVED", "reviewers": ["reviewer@scii-adversarial.invalid"],
              "source": {"uri": "https://github.com/ArduPilot/ardupilot", "commit": EXPECTED_COMMIT}}
        lab.attest("reviewer", T_REVIEW, pr, kit.commit_txt, bd.p("source/review.intoto.json"))
        bd.ev["s12"] = {"subject": "source/commit.txt", "attestation": "source/review.intoto.json"}
    # ---- сборка ----
    for sid in ("s21", "s22", "s23", "s41"):
        a = acts[sid]
        if a == "withhold" or (a == "honest" and rec[sid] == N):
            continue
        rel = "build/%s.intoto.json" % NAMES[sid]
        if a == "forge":                                   # ключ сборщика, содержимое по ожиданиям политики
            if sid == "s23":
                ptype, pr = kit.repro_pred(dig, EXPECTED_COMMIT)
            else:
                ptype, pr = kit.pred("B1", sid)
            lab.attest("builder", ptype, pr, img, bd.p(rel))
        else:                                              # честный сборщик
            if goal in ("Ц2", "Ц3"):
                b = GOAL_IMAGE[goal]
                if sid == "s23":
                    ptype, pr = kit.repro_pred(dig, None if goal == "Ц2" else EXPECTED_COMMIT)
                else:
                    ptype, pr = kit.pred(b, sid)
                lab.attest("builder", ptype, pr, img, bd.p(rel))
            elif goal == "Ц6":
                ptype, pr = kit.pred("A4", sid)
                lab.attest("builder", ptype, pr, img, bd.p(rel))
            else:                                          # Ц1, Ц4, Ц5: о подлинном образе
                ptype, pr = kit.pred("B1", sid)
                lab.attest("builder", ptype, pr, kit.genuine, bd.p(rel))
        bd.ev[sid] = {"attestation": rel}
    a = acts["s24"]
    if a != "withhold" and not (a == "honest" and rec["s24"] == N):
        rel = "build/rebuild-independent.intoto.json"
        if a == "forge":
            ptype, pr = kit.rebuild_pred(dig, dig)
            lab.attest("independent_builder", ptype, pr, img, bd.p(rel))
        elif goal in ("Ц4", "Ц5"):                         # пересборка подлинного образа до подмены
            ptype, pr = kit.pred("B1", "s24")
            lab.attest("independent_builder", ptype, pr, kit.genuine, bd.p(rel))
        else:                                              # Ц1–Ц3: честная пересборка из git даёт подлинный образ
            ptype, pr = kit.rebuild_pred(dig, kit.genuine_digest)
            lab.attest("independent_builder", ptype, pr, img, bd.p(rel))
        bd.ev["s24"] = {"attestation": rel}
    # ---- хранилище ----
    need = [s for s in ("s31", "s32") if acts[s] != "withhold" and not (acts[s] == "honest" and rec[s] == N)]
    if need:
        forged = any(acts[s] == "forge" for s in need)
        if goal == "Ц6" and not forged:
            entries = m.log("A4")
        elif goal in ("Ц4", "Ц5") and not forged:
            entries = m.log("B1")                          # журнал содержит подлинный образ
        else:                                              # загрузка образа цели (честно или подделано)
            e0 = dict(m.log("B1")[0])
            e0.update({"sha256": dig, "size": len(img)})
            entries = [e0]
        bd.put("repository/log.jsonl", "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries).encode())
        lab.sign_blob("repository", bd.p("repository/log.jsonl"), bd.p("repository/log.sigstore.json"))
        for s in need:
            bd.ev[s] = {"log": "repository/log.jsonl", "signature": "repository/log.sigstore.json"}
    # ---- пакет: подпись и проверки по образу ----
    a = acts["s42"]
    if a != "withhold":
        if goal == "Ц5" and a == "honest":
            kit.genuine_package_signature(bd)
        else:
            lab.sign_blob("vendor", bd.p("package/arducopter.apj"), bd.p("package/arducopter.apj.sigstore.json"))
        bd.ev["s42"] = {"signature": "package/arducopter.apj.sigstore.json"}
    for s in ("s51", "s52", "s53"):
        if acts[s] != "withhold":
            bd.ev[s] = {"embedded": True}
    bd.finish()
    return bd.dst


def acts_for(d_code: str, goal: str, rec: Dict[str, str], C: FrozenSet[str]) -> Dict[str, str]:
    d = DEPLOYMENTS[d_code]
    return {e: action_for(d, goal, e, C, rec[e]) for e in EVIDENCE}


# =====================================================================================================
# Прогон гейта
# =====================================================================================================
PY = os.environ.get("ADV_GATE_PYTHON") or sys.executable


def verify(bundle: str, policy: str, theta: Optional[float] = None) -> dict:
    out = bundle + ".report.json"
    cmd = [PY, "-m", "scii", "verify", "--profile", PROFILE_PATH, "--policy", policy, "--bundle", bundle,
           "--json", out, "--quiet"]
    if theta is not None:
        cmd += ["--theta", repr(theta)]
    env = dict(os.environ, PYTHONPATH=SCII_GATE, SCII_COSIGN=COSIGN)
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=SCII_GATE, timeout=600)
    rep = _rjson(out) if os.path.exists(out) else {}
    rep["_exit"] = r.returncode
    if r.returncode not in (0, 10, 20, 30):
        rep["_stderr"] = r.stderr[-600:]
    return rep


POLICY_OF = {"D1": "policy-D1.json", "D2": "policy-D2.json", "D3": "policy-D3.json"}


def run_pmi(lab: Lab, m: Material) -> dict:
    out = os.path.join(lab.work, "bundles", "pmi")
    dirs = build_pmi(lab, m, out)
    plan = _rjson(os.path.join(SCII_GATE, "testbed", "plan.json"))
    official = _rjson(os.path.join(SCII_GATE, "results", "results.json"))
    want = {sc["id"]: sc for sc in official["scenarios"]}
    rows, ok_states, ok_dec = [], 0, 0
    for sc in plan["scenarios"]:
        b = sc["id"]
        rep = verify(dirs[b], lab.policy(PMI_POLICY.get(b, "policy-D1.json")))
        got = rep.get("states", {})
        w = want[b]
        w_states = w.get("states") or sc["expect_states"]
        same_states = sum(got.get(e) == w_states.get(e) for e in EVIDENCE)
        ok_states += same_states
        same_dec = rep.get("decision") == (w.get("decision") or sc["expect"]["decision"])
        ok_dec += same_dec
        rows.append({"scenario": b, "states_equal": same_states, "decision": rep.get("decision"),
                     "decision_official": w.get("decision") or sc["expect"]["decision"], "decision_equal": same_dec,
                     "exit": rep.get("_exit"),
                     "diff": {e: [w_states.get(e), got.get(e), rep.get("reasons", {}).get(e)] for e in EVIDENCE
                              if got.get(e) != w_states.get(e)}})
    return {"states_equal": ok_states, "states_total": 17 * len(rows), "decisions_equal": ok_dec,
            "decisions_total": len(rows), "rows": rows}


def run_goals(lab: Lab, m: Material, analysis: dict, singles: bool = True) -> dict:
    kit = GoalKit(lab, m)
    rows = []
    base = os.path.join(lab.work, "bundles", "goals")
    from .semantics import compromise_sets, members
    for d_code in ("D1", "D2", "D3"):
        d, rs = DEPLOYMENTS[d_code], RULESETS[d_code]
        theta = None if d_code != "D2" else rs.theta
        for goal in GOALS:
            seen: Dict[str, FrozenSet[str]] = {}
            for U in compromise_sets(d, "separate", goal):
                C = members(d, "separate", U)
                key = "".join(best_record(d, goal, C)[e] for e in EVIDENCE)
                if key not in seen or len(C) < len(seen[key]):
                    seen[key] = C
            for i, (key, C) in enumerate(sorted(seen.items(), key=lambda kv: (len(kv[1]), sorted(kv[1])))):
                rec = dict(zip(EVIDENCE, key))
                acts = acts_for(d_code, goal, rec, C)
                dst = os.path.join(base, d_code, goal, "r%03d" % i)
                build_goal(kit, d_code, goal, rec, acts, dst)
                rep = verify(dst, lab.policy(POLICY_OF[d_code]), theta)
                rows.append(_compare("best", d_code, goal, sorted(C), rec, acts, rep, rs))
                shutil.rmtree(dst, ignore_errors=True)
            if singles and d_code == "D1":
                rows += _singles(kit, lab, d_code, goal, base, rs)
    return summarize_emulation(rows)


def _singles(kit, lab, d_code, goal, base, rs) -> List[dict]:
    """Комплект без действий нарушителя, кроме внедрения, и комплекты с каждым одиночным действием."""
    d = DEPLOYMENTS[d_code]
    entry = GOAL[goal]["entry"]
    out = []
    honest = {e: honest_state(d, goal, e) for e in EVIDENCE}
    variants = [("honest", None, None)]
    for e in EVIDENCE:
        prod = PRODUCER.get(e)
        if prod is not None and e in d.anchors and honest[e] != P:
            variants.append(("forge", e, frozenset({entry, prod})))
        if honest[e] != N:
            variants.append(("withhold", e, frozenset({entry, "CH"})))
        if e in REPLAY and REPLAY[e] != honest[e]:
            variants.append(("replay", e, frozenset({entry, "CH"})))
    for j, (kind, e, C) in enumerate(variants):
        rec, acts = dict(honest), {x: "honest" for x in EVIDENCE}
        Cs = frozenset({entry}) if C is None else C
        if e is not None:
            rec[e] = {"forge": P, "withhold": N, "replay": REPLAY.get(e)}[kind]
            acts[e] = kind
        dst = os.path.join(base, d_code, goal, "s%03d" % j)
        build_goal(kit, d_code, goal, rec, acts, dst)
        rep = verify(dst, lab.policy(POLICY_OF[d_code]), None)
        out.append(_compare("single:%s:%s" % (kind, e), d_code, goal, sorted(Cs), rec, acts, rep, rs))
        shutil.rmtree(dst, ignore_errors=True)
    return out


def _compare(kind, d_code, goal, C, rec, acts, rep, rs) -> dict:
    got = rep.get("states", {})
    diff = {e: [rec[e], got.get(e), rep.get("reasons", {}).get(e)] for e in EVIDENCE if got.get(e) != rec[e]}
    model_dec = rs.decide("П10", rec)
    return {"kind": kind, "deployment": d_code, "goal": goal, "participants": C,
            "record": "".join(rec[e] for e in EVIDENCE), "actions": {e: a for e, a in acts.items() if a != "honest"},
            "gate_decision": rep.get("decision"), "model_decision": model_dec, "exit": rep.get("_exit"),
            "states_equal": not diff, "decision_equal": rep.get("decision") == model_dec, "diff": diff,
            "rules_on_gate_states": rs.all(got) if len(got) == 17 else None}


def summarize_emulation(rows: List[dict]) -> dict:
    best = [r for r in rows if r["kind"] == "best"]
    singles = [r for r in rows if r["kind"] != "best"]
    def agg(rs_):
        return {"bundles": len(rs_), "states_equal": sum(r["states_equal"] for r in rs_),
                "decisions_equal": sum(r["decision_equal"] for r in rs_)}
    by = {}
    for r in best:
        by.setdefault(r["deployment"], []).append(r)
    return {"best": agg(best), "best_by_deployment": {k: agg(v) for k, v in by.items()}, "singles": agg(singles),
            "mismatches": [r for r in rows if not (r["states_equal"] and r["decision_equal"])], "rows": rows}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adv.emulate")
    ap.add_argument("cmd", choices=["keys", "pmi", "goals", "all"])
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "emulation.json"))
    ap.add_argument("--no-singles", action="store_true")
    a = ap.parse_args(argv)
    lab = Lab()
    t0 = time.time()
    lab.make_keys()
    lab.make_policies()
    if a.cmd == "keys":
        print("ключи и политики: %s" % lab.pol)
        return 0
    m = Material()
    cv = _run([COSIGN, "version"]).stdout.decode()
    res = {"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "cosign": cv.split("GitVersion:")[-1].split()[0] if "GitVersion:" in cv else cv.strip()[:40]}
    if a.cmd in ("pmi", "all"):
        res["pmi"] = run_pmi(lab, m)
        print("Г0: состояния %d из %d, решения %d из %d" % (res["pmi"]["states_equal"], res["pmi"]["states_total"],
                                                          res["pmi"]["decisions_equal"], res["pmi"]["decisions_total"]))
    if a.cmd in ("goals", "all"):
        res["goals"] = run_goals(lab, m, {}, singles=not a.no_singles)
        g = res["goals"]
        print("Г7: лучшие записи %d комплектов, совпали состояния %d, решения %d; одиночные действия %d, %d, %d"
              % (g["best"]["bundles"], g["best"]["states_equal"], g["best"]["decisions_equal"],
                 g["singles"]["bundles"], g["singles"]["states_equal"], g["singles"]["decisions_equal"]))
    res["seconds"] = round(time.time() - t0, 1)
    _wjson(a.out, res)
    print("записано %s (%.0f с)" % (a.out, res["seconds"]))
    bad = (res.get("pmi", {}).get("decisions_equal", 0) != res.get("pmi", {}).get("decisions_total", 0)
           or bool(res.get("goals", {}).get("mismatches")))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
