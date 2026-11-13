# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import json
import os
import typing as t
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import dpapi_ng
import dpapi_ng._blob as blob
import dpapi_ng._client as client
import dpapi_ng._gkdi as gkdi

from .conftest import get_test_data

# These scenarios were created with tests/integration/files/New-KdsRootKey.ps1
# and tests/integration/files/ConvertTo-DpapiNgBlob.ps1


def _load_root_key(scenario: str) -> tuple[bytes, dpapi_ng.KeyCache]:
    data = json.loads(get_test_data(f"{scenario}.json"))

    cache = dpapi_ng.KeyCache()
    cache.load_key(
        key=base64.b16decode(data["RootKeyData"]),
        root_key_id=uuid.UUID(data["RootKeyId"]),
        version=data["Version"],
        kdf_algorithm=data["KdfAlgorithm"],
        kdf_parameters=base64.b16decode(data["KdfParameters"]),
        secret_algorithm=data["SecretAgreementAlgorithm"],
        secret_parameters=base64.b16decode(data["SecretAgreementParameters"]),
        private_key_length=data["PrivateKeyLength"],
        public_key_length=data["PublicKeyLength"],
    )

    return base64.b16decode(data["Data"]), cache


@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha1_nonce",
        "kdf_sha256_nonce",
        "kdf_sha384_nonce",
        "kdf_sha512_nonce",
    ],
)
def test_protect_secret(scenario: str) -> None:
    test_data = b"schorschii"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"

    key_cache = _load_root_key(scenario)[1]
    test_root_key_identifier = list(key_cache._root_keys.keys())[0]

    encrypted = dpapi_ng.ncrypt_protect_secret(
        test_data,
        test_protection_descriptor,
        root_key_identifier=test_root_key_identifier,
        cache=key_cache,
    )
    decrypted = dpapi_ng.ncrypt_unprotect_secret(encrypted, cache=key_cache)
    assert test_data == decrypted


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha1_nonce",
        "kdf_sha256_nonce",
        "kdf_sha384_nonce",
        "kdf_sha512_nonce",
    ],
)
async def test_async_protect_secret(scenario: str) -> None:
    test_data = b"schorschii"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"

    key_cache = _load_root_key(scenario)[1]
    test_root_key_identifier = list(key_cache._root_keys.keys())[0]

    encrypted = await dpapi_ng.async_ncrypt_protect_secret(
        test_data,
        test_protection_descriptor,
        root_key_identifier=test_root_key_identifier,
        cache=key_cache,
    )
    decrypted = await dpapi_ng.async_ncrypt_unprotect_secret(encrypted, cache=key_cache)
    assert test_data == decrypted


@pytest.mark.parametrize(
    "kdf_algo, secret_algo",
    [
        ("SHA1", "DH"),
        ("SHA1", "ECDH_P256"),
        ("SHA1", "ECDH_P384"),
        ("SHA256", "DH"),
        ("SHA256", "ECDH_P256"),
        ("SHA256", "ECDH_P384"),
        ("SHA384", "DH"),
        ("SHA384", "ECDH_P256"),
        ("SHA384", "ECDH_P384"),
        ("SHA512", "DH"),
        ("SHA512", "ECDH_P256"),
        ("SHA512", "ECDH_P384"),
    ],
)
def test_protect_secret_public_key(
    kdf_algo: str,
    secret_algo: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_data = b"schorschii"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"

    private_key_length, public_key_length = {
        "DH": (512, 2048),
        "ECDH_P256": (256, 256),
        "ECDH_P384": (384, 384),
        "ECDH_P521": (521, 521),
    }[secret_algo]

    root_key_id = uuid.uuid4()
    key_cache = dpapi_ng.KeyCache()
    key_cache.load_key(
        os.urandom(64),
        root_key_id=root_key_id,
        version=1,
        kdf_parameters=gkdi.KDFParameters(kdf_algo).pack(),
        secret_algorithm=secret_algo,
        private_key_length=private_key_length,
        public_key_length=public_key_length,
    )

    original_get_gke = client._get_protection_gke_from_cache

    def get_protection_gke(
        root_key_identifier: t.Optional[uuid.UUID],
        target_sd: bytes,
        cache: client.KeyCache,
    ) -> gkdi.GroupKeyEnvelope:
        gke = original_get_gke(root_key_identifier, target_sd, cache)
        assert gke

        private_key = gkdi.kdf(
            gkdi.KDFParameters.unpack(gke.kdf_parameters).hash_algorithm,
            gke.l2_key,
            gkdi.KDS_SERVICE_LABEL,
            (gke.secret_algorithm + "\0").encode("utf-16-le"),
            (gke.private_key_length // 8),
        )

        if gke.secret_algorithm == "DH":
            secret_params = gkdi.FFCDHParameters.unpack(gke.secret_parameters)
            public_key = pow(
                secret_params.generator,
                int.from_bytes(private_key, byteorder="big"),
                secret_params.field_order,
            )

            pub_key = gkdi.FFCDHKey(
                key_length=secret_params.key_length,
                field_order=secret_params.field_order,
                generator=secret_params.generator,
                public_key=public_key,
            ).pack()
        else:
            curve, curve_name = {
                "ECDH_P256": (ec.SECP256R1(), "P256"),
                "ECDH_P384": (ec.SECP384R1(), "P384"),
                "ECDH_P521": (ec.SECP521R1(), "P521"),
            }[gke.secret_algorithm]

            ecdh_private = ec.derive_private_key(
                int.from_bytes(private_key, byteorder="big"),
                curve,
            )
            key_numbers = ecdh_private.public_key().public_numbers()

            pub_key = gkdi.ECDHKey(
                curve_name=curve_name,
                key_length=ecdh_private.key_size // 8,
                x=key_numbers.x,
                y=key_numbers.y,
            ).pack()

        object.__setattr__(gke, "flags", 1)
        object.__setattr__(gke, "l2_key", pub_key)

        return gke

    monkeypatch.setattr(client, "_get_protection_gke_from_cache", get_protection_gke)

    encrypted = dpapi_ng.ncrypt_protect_secret(
        test_data,
        test_protection_descriptor,
        root_key_identifier=root_key_id,
        cache=key_cache,
    )
    decrypted = dpapi_ng.ncrypt_unprotect_secret(encrypted, cache=key_cache)
    assert test_data == decrypted


@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha1_nonce",
        "kdf_sha256_nonce",
        "kdf_sha384_nonce",
        "kdf_sha512_nonce",
        "kdf_sha1_dh",
        "kdf_sha256_dh",
        "kdf_sha384_dh",
        "kdf_sha512_dh",
        "kdf_sha1_ecdh_p256",
        "kdf_sha256_ecdh_p256",
        "kdf_sha384_ecdh_p256",
        "kdf_sha512_ecdh_p256",
        "kdf_sha1_ecdh_p384",
        "kdf_sha256_ecdh_p384",
        "kdf_sha384_ecdh_p384",
        "kdf_sha512_ecdh_p384",
    ],
)
def test_unprotect_secret(
    scenario: str,
) -> None:
    expected = b"\x00"

    data, key_cache = _load_root_key(scenario)

    actual = dpapi_ng.ncrypt_unprotect_secret(data, cache=key_cache)
    assert actual == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha1_nonce",
        "kdf_sha256_nonce",
        "kdf_sha384_nonce",
        "kdf_sha512_nonce",
        "kdf_sha1_dh",
        "kdf_sha256_dh",
        "kdf_sha384_dh",
        "kdf_sha512_dh",
        "kdf_sha1_ecdh_p256",
        "kdf_sha256_ecdh_p256",
        "kdf_sha384_ecdh_p256",
        "kdf_sha512_ecdh_p256",
        "kdf_sha1_ecdh_p384",
        "kdf_sha256_ecdh_p384",
        "kdf_sha384_ecdh_p384",
        "kdf_sha512_ecdh_p384",
    ],
)
async def test_async_unprotect_secret(
    scenario: str,
) -> None:
    expected = b"\x00"

    data, key_cache = _load_root_key(scenario)

    actual = await dpapi_ng.async_ncrypt_unprotect_secret(data, cache=key_cache)
    assert actual == expected


class _CountingKDF:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(
        self,
        algorithm,
        secret,
        label,
        context,
        length,
    ) -> bytes:
        self.calls += 1
        return bytes([self.calls % 256]) * length


def _make_blob(
    l0: int,
    l1: int,
    l2: int,
) -> blob.DPAPINGBlob:
    descriptor = blob.ProtectionDescriptor.parse("S-1-5-21-2185496602-3367037166-1388177638-1103")
    key_id = blob.KeyIdentifier(
        version=1,
        flags=0,
        l0=l0,
        l1=l1,
        l2=l2,
        root_key_identifier=uuid.UUID(int=0),
        key_info=b"\x00" * 32,
        domain_name="domain.test",
        forest_name="domain.test",
    )
    return blob.DPAPINGBlob(
        key_identifier=key_id,
        protection_descriptor=descriptor,
        enc_cek=b"\x00" * 40,
        enc_cek_algorithm=client.AlgorithmOID.AES256_WRAP,
        enc_cek_parameters=None,
        enc_content=b"",
        enc_content_algorithm=client.AlgorithmOID.AES256_GCM,
        enc_content_parameters=None,
    )


def _make_envelope(
    l0: int,
    l1: int,
    l2: int,
) -> gkdi.GroupKeyEnvelope:
    return gkdi.GroupKeyEnvelope(
        version=1,
        flags=2,
        l0=l0,
        l1=l1,
        l2=l2,
        root_key_identifier=uuid.UUID(int=0),
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=gkdi.KDFParameters("SHA512").pack(),
        secret_algorithm="DH",
        secret_parameters=b"",
        private_key_length=512,
        public_key_length=2048,
        domain_name="domain.test",
        forest_name="domain.test",
        l1_key=b"\x10" * 64,
        l2_key=b"\x20" * 64,
    )


def test_unprotect_rejects_unreachable_cache_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The cache holds a seed for (L0, L1=5, L2=6). A negative L2 request passes
    # the cache freshness check (6 >= -1) but is not a reachable index, so
    # validation must reject it before any KDF and without a network fallback.
    key_cache = dpapi_ng.KeyCache()
    target_sd = blob.ProtectionDescriptor.parse(
        "S-1-5-21-2185496602-3367037166-1388177638-1103"
    ).get_target_sd()
    key_cache._store_key(target_sd, _make_envelope(361, 5, 6))

    # A negative index cannot be serialized, so inject the already-unpacked
    # blob instead of round-tripping it through pack/unpack.
    invalid_blob = _make_blob(361, 5, -1)
    monkeypatch.setattr(blob.DPAPINGBlob, "unpack", classmethod(lambda cls, data: invalid_blob))

    def fail_rpc(*args, **kwargs):
        raise AssertionError("a cache hit must not fall back to the network")

    monkeypatch.setattr(client, "_sync_get_key", fail_rpc)
    counting_kdf = _CountingKDF()
    monkeypatch.setattr(gkdi, "kdf", counting_kdf)

    with pytest.raises(ValueError, match="Requested L2 index -1 is outside the valid range of 0-31"):
        dpapi_ng.ncrypt_unprotect_secret(b"not-a-real-blob", server="dc.domain.test", cache=key_cache)

    assert counting_kdf.calls == 0


def test_unprotect_rejects_unreachable_network_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A fresh (empty) cache forces a GetKey RPC. The envelope returned by the
    # server is validated through the same rule before any derivation runs.
    key_cache = dpapi_ng.KeyCache()
    monkeypatch.setattr(client, "_sync_get_key", lambda *args, **kwargs: _make_envelope(361, 5, 6))

    data = _make_blob(361, 5, 7).pack()

    counting_kdf = _CountingKDF()
    monkeypatch.setattr(gkdi, "kdf", counting_kdf)

    with pytest.raises(ValueError, match="L2 index 7 is not reachable from the seed L2 index 6"):
        dpapi_ng.ncrypt_unprotect_secret(data, server="dc.domain.test", cache=key_cache)

    assert counting_kdf.calls == 0
