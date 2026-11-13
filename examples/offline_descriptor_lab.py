#!/usr/bin/env python3
"""Offline DPAPI-NG lab with a synthetic root key.

This script never contacts a domain controller. It shows that the protection
descriptor (SID) is KDF input: different descriptors produce different L1/L2
seeds and KEKs, and swapping a descriptor breaks unwrap. It also shows the
limit of that result: a cache hit performs no caller authentication, so a
successful decrypt is not proof that the requesting operator is authorised.

Run from the repository root:

    .venv/bin/python examples/offline_descriptor_lab.py
"""

from __future__ import annotations

import dataclasses
import hashlib
import uuid

import dpapi_ng
from dpapi_ng import _gkdi as gkdi
from dpapi_ng import _blob as blob

ROOT_KEY_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
SYNTHETIC_ROOT_KEY = bytes(range(64))  # NOT a real domain root key
SID_ALICE = "S-1-5-21-1-2-3-1001"
SID_BOB = "S-1-5-21-1-2-3-1002"
FIXED_KEY_INFO = b"lab-key-info-0123456789abcdef"


def make_cache() -> dpapi_ng.KeyCache:
    cache = dpapi_ng.KeyCache()
    cache.load_key(
        SYNTHETIC_ROOT_KEY,
        ROOT_KEY_ID,
        version=1,
        kdf_parameters=gkdi.KDFParameters("SHA256").pack(),
        secret_algorithm="ECDH_P256",
        private_key_length=256,
        public_key_length=256,
    )
    return cache


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def derive(cache: dpapi_ng.KeyCache, sid: str, l0: int = 10, l1: int = 5, l2: int = 3) -> dict[str, bytes]:
    target_sd = blob.SIDDescriptor(sid).get_target_sd()
    gke = cache._get_key(target_sd, ROOT_KEY_ID, l0, l1, l2)
    if gke is None:
        raise RuntimeError("synthetic root key was not loaded")

    kdf_parameters = gkdi.KDFParameters.unpack(gke.kdf_parameters)
    l2_key = gkdi.compute_l2_key(kdf_parameters.hash_algorithm, l1, l2, gke)
    kek = gkdi.kdf(
        kdf_parameters.hash_algorithm,
        l2_key,
        gkdi.KDS_SERVICE_LABEL,
        FIXED_KEY_INFO,
        32,
    )
    return {"target_sd": target_sd, "l1_key": gke.l1_key, "l2_key": l2_key, "kek": kek}


def main() -> None:
    print("Offline DPAPI-NG boundary lab (synthetic root key; no DC contacted)")
    print(f"root_key_id={ROOT_KEY_ID} root_key=sha256:{digest(SYNTHETIC_ROOT_KEY)}\n")

    cache = make_cache()

    print("[1] Different descriptors derive different key material")
    results = {sid: derive(cache, sid) for sid in (SID_ALICE, SID_BOB)}
    print(f"{'sid':34} {'target_sd':20} {'l1_key':20} {'l2_key':20} {'kek':20}")
    for sid, values in results.items():
        print(
            f"{sid:34} {digest(values['target_sd']):20} {digest(values['l1_key']):20} "
            f"{digest(values['l2_key']):20} {digest(values['kek']):20}"
        )
    assert results[SID_ALICE]["kek"] != results[SID_BOB]["kek"]

    print("\n[2] The same descriptor is deterministic")
    assert derive(cache, SID_ALICE)["kek"] == results[SID_ALICE]["kek"]
    print("same SID -> same KEK [ok]")

    print("\n[3] Other KDF inputs also change the KEK")
    baseline_kek = results[SID_ALICE]["kek"]
    for label, changed in (
        ("l0=11", derive(cache, SID_ALICE, l0=11)),
        ("l1=4", derive(cache, SID_ALICE, l1=4)),
        ("l2=2", derive(cache, SID_ALICE, l2=2)),
    ):
        print(f"{label:6} -> KEK sha256:{digest(changed['kek'])} differs={changed['kek'] != baseline_kek}")

    print("\n[4] A blob keeps its descriptor binding")
    protected = dpapi_ng.ncrypt_protect_secret(
        b"restore-me",
        SID_ALICE,
        root_key_identifier=ROOT_KEY_ID,
        cache=cache,
        cache_only=True,
    )
    print(f"decrypt as protected: {dpapi_ng.ncrypt_unprotect_secret(protected, cache=cache, cache_only=True)!r}")

    parsed = blob.DPAPINGBlob.unpack(protected)
    tampered = dataclasses.replace(parsed, protection_descriptor=blob.SIDDescriptor(SID_BOB))
    try:
        dpapi_ng.ncrypt_unprotect_secret(tampered.pack(), cache=cache, cache_only=True)
    except Exception as exc:
        print(f"descriptor swapped to SID B -> {type(exc).__name__} (expected)")
    else:
        raise AssertionError("descriptor substitution should not decrypt")

    print("\n[5] A cache hit does not authenticate the caller")
    recovered = dpapi_ng.ncrypt_unprotect_secret(
        protected,
        username="not-a-domain-user",
        password="irrelevant",
        cache=cache,
        cache_only=True,
    )
    print(f"decrypt with bogus credentials: {recovered!r}")
    print("=> KDF binding held, but nothing checked that this operator is authorised.")

    print("\n[6] Fail-closed when the key is absent")
    try:
        dpapi_ng.ncrypt_unprotect_secret(protected, cache=dpapi_ng.KeyCache(), cache_only=True)
    except ValueError as exc:
        print(f"cache_only miss -> ValueError: {exc}")
    else:
        raise AssertionError("cache_only should fail closed on a miss")

    print("\nBoundary summary: descriptor != authorization.")


if __name__ == "__main__":
    main()
