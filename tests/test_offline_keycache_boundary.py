# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import hashlib
import typing as t
import uuid

import pytest
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

import dpapi_ng
import dpapi_ng._client as client
from dpapi_ng import _blob as blob
from dpapi_ng import _gkdi as gkdi

ROOT_KEY_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
ROOT_KEY = bytes(range(64))
ROTATED_ROOT_KEY = bytes(range(64, 128))
SID_A = "S-1-5-21-1-2-3-1001"
SID_B = "S-1-5-21-1-2-3-1002"


def _cache(
    key: bytes = ROOT_KEY,
    root_key_id: uuid.UUID = ROOT_KEY_ID,
) -> dpapi_ng.KeyCache:
    cache = dpapi_ng.KeyCache()
    cache.load_key(
        key,
        root_key_id,
        version=1,
        kdf_parameters=gkdi.KDFParameters("SHA256").pack(),
        secret_algorithm="ECDH_P256",
        private_key_length=256,
        public_key_length=256,
    )
    return cache


def _sd(sid: str) -> bytes:
    return blob.SIDDescriptor(sid).get_target_sd()


def _keys(
    cache: dpapi_ng.KeyCache,
    sid: str,
    l0: int = 10,
    l1: int = 5,
    l2: int = 3,
    key_info: bytes = b"fixed-key-info-0123456789abcdef",
) -> tuple[bytes, bytes]:
    gke = cache._get_key(_sd(sid), ROOT_KEY_ID, l0, l1, l2)
    assert gke is not None

    kdf_parameters = gkdi.KDFParameters.unpack(gke.kdf_parameters)
    l2_key = gkdi.compute_l2_key(kdf_parameters.hash_algorithm, l1, l2, gke)
    kek = gkdi.kdf(
        kdf_parameters.hash_algorithm,
        l2_key,
        gkdi.KDS_SERVICE_LABEL,
        key_info,
        32,
    )
    return l2_key, kek


def _public_envelope() -> gkdi.GroupKeyEnvelope:
    return gkdi.GroupKeyEnvelope(
        version=1,
        flags=1,
        l0=10,
        l1=5,
        l2=3,
        root_key_identifier=ROOT_KEY_ID,
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=gkdi.KDFParameters("SHA256").pack(),
        secret_algorithm="ECDH_P256",
        secret_parameters=b"",
        private_key_length=256,
        public_key_length=256,
        domain_name="domain.test",
        forest_name="domain.test",
        l1_key=b"",
        l2_key=b"",
    )


def test_different_descriptors_derive_different_keys() -> None:
    """The target SD is KDF input, so distinct descriptors give distinct keys."""
    cache = _cache()

    sd_a = _sd(SID_A)
    sd_b = _sd(SID_B)
    assert sd_a != sd_b

    l2_a, kek_a = _keys(cache, SID_A)
    l2_b, kek_b = _keys(cache, SID_B)
    assert l2_a != l2_b
    assert kek_a != kek_b


def test_same_descriptor_is_deterministic() -> None:
    cache = _cache()

    l2_first, kek_first = _keys(cache, SID_A)
    l2_second, kek_second = _keys(cache, SID_A)
    assert l2_first == l2_second
    assert kek_first == kek_second


def test_changing_request_inputs_changes_the_kek() -> None:
    cache = _cache()
    _, baseline = _keys(cache, SID_A)

    _, different_l1 = _keys(cache, SID_A, l1=4)
    _, different_l2 = _keys(cache, SID_A, l2=2)
    _, different_info = _keys(cache, SID_A, key_info=b"different-key-info-0123456")

    assert baseline != different_l1
    assert baseline != different_l2
    assert baseline != different_info


def test_blob_descriptor_substitution_fails_unwrap() -> None:
    cache = _cache()
    protected = dpapi_ng.ncrypt_protect_secret(
        b"recoverable secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=cache,
        cache_only=True,
    )

    original = blob.DPAPINGBlob.unpack(protected)
    substituted = dataclasses.replace(original, protection_descriptor=blob.SIDDescriptor(SID_B))

    with pytest.raises(InvalidUnwrap):
        dpapi_ng.ncrypt_unprotect_secret(substituted.pack(), cache=cache, cache_only=True)


def test_cache_only_never_contacts_a_dc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = _cache()
    protected = dpapi_ng.ncrypt_protect_secret(
        b"offline secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=cache,
        cache_only=True,
    )

    def fail_if_called(*args: object, **kwargs: object) -> t.Any:
        raise AssertionError("offline recovery must not make an RPC call")

    monkeypatch.setattr(client, "lookup_dc", fail_if_called)
    monkeypatch.setattr(client, "_sync_get_key", fail_if_called)

    recovered = dpapi_ng.ncrypt_unprotect_secret(protected, cache=cache, cache_only=True)
    assert recovered == b"offline secret"


def test_cache_only_fails_closed_without_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = dpapi_ng.ncrypt_protect_secret(
        b"secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=_cache(),
        cache_only=True,
    )

    def fail_if_called(*args: object, **kwargs: object) -> t.Any:
        raise AssertionError("cache_only must not fall back to DNS or RPC")

    monkeypatch.setattr(client, "lookup_dc", fail_if_called)
    monkeypatch.setattr(client, "_sync_get_key", fail_if_called)

    with pytest.raises(ValueError, match="no domain controller was contacted"):
        dpapi_ng.ncrypt_unprotect_secret(protected, cache=dpapi_ng.KeyCache(), cache_only=True)


@pytest.mark.asyncio
async def test_async_cache_only_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = dpapi_ng.ncrypt_protect_secret(
        b"secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=_cache(),
        cache_only=True,
    )

    async def fail_if_called(*args: object, **kwargs: object) -> t.Any:
        raise AssertionError("cache_only must not fall back to DNS or RPC")

    monkeypatch.setattr(client, "async_lookup_dc", fail_if_called)
    monkeypatch.setattr(client, "_async_get_key", fail_if_called)

    with pytest.raises(ValueError, match="no domain controller was contacted"):
        await dpapi_ng.async_ncrypt_unprotect_secret(
            protected,
            cache=dpapi_ng.KeyCache(),
            cache_only=True,
        )


def test_cached_key_ignores_caller_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cache hit never authenticates: credentials are not part of the cache key."""
    cache = _cache()
    protected = dpapi_ng.ncrypt_protect_secret(
        b"secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=cache,
        cache_only=True,
    )

    def fail_if_called(*args: object, **kwargs: object) -> t.Any:
        raise AssertionError("cache hit must not authenticate a caller")

    monkeypatch.setattr(client, "_sync_get_key", fail_if_called)

    recovered = dpapi_ng.ncrypt_unprotect_secret(
        protected,
        username="unauthorised-user",
        password="not-a-real-password",
        cache=cache,
        cache_only=True,
    )
    assert recovered == b"secret"


def test_online_authorization_denial_surfaces_as_public_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GetKey returning a public-key envelope is the online denial signal."""
    protected = dpapi_ng.ncrypt_protect_secret(
        b"secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=_cache(),
        cache_only=True,
    )

    def deny(*args: object, **kwargs: object) -> gkdi.GroupKeyEnvelope:
        return _public_envelope()

    monkeypatch.setattr(client, "_sync_get_key", deny)

    with pytest.raises(ValueError, match="Current user is not authorized"):
        dpapi_ng.ncrypt_unprotect_secret(
            protected,
            server="dc01.domain.test",
            cache=dpapi_ng.KeyCache(),
        )


def test_root_key_reload_invalidates_derived_seeds() -> None:
    """A root key id is an identity, not a version, so reloading new material clears seeds."""
    cache = _cache()
    _, kek_old = _keys(cache, SID_A)

    cache.load_key(
        ROTATED_ROOT_KEY,
        ROOT_KEY_ID,
        version=1,
        kdf_parameters=gkdi.KDFParameters("SHA256").pack(),
        secret_algorithm="ECDH_P256",
        private_key_length=256,
        public_key_length=256,
    )

    _, kek_new = _keys(cache, SID_A)
    _, kek_fresh_cache = _keys(_cache(ROTATED_ROOT_KEY), SID_A)
    assert kek_new != kek_old
    assert kek_new == kek_fresh_cache


def test_stale_blob_fails_after_root_key_rotation() -> None:
    """A blob made under the old material must not open under the rotated key."""
    protected_old = dpapi_ng.ncrypt_protect_secret(
        b"old secret",
        SID_A,
        root_key_identifier=ROOT_KEY_ID,
        cache=_cache(ROOT_KEY),
        cache_only=True,
    )

    with pytest.raises(InvalidUnwrap):
        dpapi_ng.ncrypt_unprotect_secret(protected_old, cache=_cache(ROTATED_ROOT_KEY), cache_only=True)


def test_descriptor_bytes_are_a_pure_function_of_the_sid() -> None:
    assert _sd(SID_A) == _sd(SID_A)
    assert hashlib.sha256(_sd(SID_A)).digest() != hashlib.sha256(_sd(SID_B)).digest()

    assert _sd(SID_A) == bytes.fromhex(
        "0100048054000000600000000000000014000000020040000200000000002400030000"
        "00010500000000000515000000010000000200000003000000e903000000001400020000"
        "000101000000000001000000000101000000000005120000000101000000000005120000"
        "00"
    )
