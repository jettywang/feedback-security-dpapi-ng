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
import dpapi_ng._client as client
import dpapi_ng._gkdi as gkdi
from dpapi_ng._asn1 import ASN1Reader
from dpapi_ng._blob import BlobParseStrategy, DPAPINGBlob, EncryptedContentSource

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


def _load_nonce_cache() -> tuple[str, dpapi_ng.KeyCache]:
    scenario = "kdf_sha256_nonce"
    _, cache = _load_root_key(scenario)
    root_key_identifier = list(cache._root_keys.keys())[0]
    return str(root_key_identifier), cache


def test_unprotect_secret_both_forms_same_plaintext() -> None:
    plaintext = b"dual-form-secret"
    descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    root_key_id, cache = _load_nonce_cache()

    embedded_blob = dpapi_ng.ncrypt_protect_secret(
        plaintext,
        descriptor,
        root_key_identifier=uuid.UUID(root_key_id),
        cache=cache,
    )

    # Rebuild the exact same protected content in the LAPS (appended) form.
    parsed = DPAPINGBlob.unpack(embedded_blob)
    assert parsed.enc_content_source == EncryptedContentSource.EMBEDDED
    appended_blob = parsed.pack(blob_in_envelope=False)
    assert DPAPINGBlob.unpack(appended_blob).enc_content_source == EncryptedContentSource.APPENDED

    # Both legal forms return the same plaintext through the public entry.
    assert dpapi_ng.ncrypt_unprotect_secret(embedded_blob, cache=cache) == plaintext
    assert dpapi_ng.ncrypt_unprotect_secret(appended_blob, cache=cache) == plaintext

    # Explicit strategies also succeed for their matching form.
    assert (
        dpapi_ng.ncrypt_unprotect_secret(
            appended_blob,
            cache=cache,
            parse_strategy=BlobParseStrategy.APPENDED,
        )
        == plaintext
    )
    assert (
        dpapi_ng.ncrypt_unprotect_secret(
            embedded_blob,
            cache=cache,
            parse_strategy=BlobParseStrategy.EMBEDDED,
        )
        == plaintext
    )


@pytest.mark.asyncio
async def test_async_unprotect_secret_both_forms_same_plaintext() -> None:
    plaintext = b"dual-form-secret-async"
    descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    root_key_id, cache = _load_nonce_cache()

    embedded_blob = await dpapi_ng.async_ncrypt_protect_secret(
        plaintext,
        descriptor,
        root_key_identifier=uuid.UUID(root_key_id),
        cache=cache,
    )
    appended_blob = DPAPINGBlob.unpack(embedded_blob).pack(blob_in_envelope=False)

    assert await dpapi_ng.async_ncrypt_unprotect_secret(embedded_blob, cache=cache) == plaintext
    assert await dpapi_ng.async_ncrypt_unprotect_secret(appended_blob, cache=cache) == plaintext


def test_unprotect_secret_dual_conflict_rejected_before_decryption(monkeypatch: pytest.MonkeyPatch) -> None:
    plaintext = b"ambiguous-secret"
    descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    root_key_id, cache = _load_nonce_cache()

    embedded_blob = dpapi_ng.ncrypt_protect_secret(
        plaintext,
        descriptor,
        root_key_identifier=uuid.UUID(root_key_id),
        cache=cache,
    )
    embedded_content = DPAPINGBlob.unpack(embedded_blob).enc_content

    # Both locations carry content at once.
    conflict_blob = embedded_blob + embedded_content

    def fail_decrypt(*args: t.Any, **kwargs: t.Any) -> bytes:
        raise AssertionError("decryption must not be attempted for an ambiguous blob")

    monkeypatch.setattr(client, "_decrypt_blob", fail_decrypt)

    for strategy in BlobParseStrategy:
        with pytest.raises(ValueError, match="ambiguous|unexpected trailing|as well as"):
            dpapi_ng.ncrypt_unprotect_secret(
                conflict_blob,
                cache=cache,
                parse_strategy=strategy,
            )


def test_unprotect_secret_second_envelope_rejected_before_decryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = b"two-envelopes"
    descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    root_key_id, cache = _load_nonce_cache()

    embedded_blob = dpapi_ng.ncrypt_protect_secret(
        plaintext,
        descriptor,
        root_key_identifier=uuid.UUID(root_key_id),
        cache=cache,
    )
    # An empty LAPS envelope followed by a full embedded envelope.
    empty_envelope = DPAPINGBlob.unpack(embedded_blob).pack(blob_in_envelope=False)
    header = ASN1Reader(empty_envelope).peek_header()
    empty_envelope = empty_envelope[: header.tag_length + header.length]
    two_envelopes = empty_envelope + embedded_blob

    def fail_decrypt(*args: t.Any, **kwargs: t.Any) -> bytes:
        raise AssertionError("decryption must not be attempted when a second envelope is present")

    monkeypatch.setattr(client, "_decrypt_blob", fail_decrypt)

    for strategy in BlobParseStrategy:
        with pytest.raises(ValueError, match="second complete CMS EnvelopedData"):
            dpapi_ng.ncrypt_unprotect_secret(
                two_envelopes,
                cache=cache,
                parse_strategy=strategy,
            )
