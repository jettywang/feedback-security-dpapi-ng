# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import os
import typing as t
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import dpapi_ng
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


FIXED_TIME = 179456765400000000


def _fixed_time() -> int:
    return client._get_key_indices(FIXED_TIME)


def _set_fixed_time(monkeypatch: pytest.MonkeyPatch) -> None:
    indices = _fixed_time()
    monkeypatch.setattr(
        client,
        "_get_current_time",
        lambda: indices.l0 * client._L0_TIME_SLOT + indices.l1 * client._L1_TIME_SLOT + indices.l2 * client._TIME_SLOT,
    )


class _LocalProvider(dpapi_ng.KeyProvider):
    """A local provider backed by an offline root key cache."""

    def __init__(self, cache: dpapi_ng.KeyCache, seed_at_l1: int = -1, seed_at_l2: int = -1) -> None:
        self.cache = cache
        self.calls: t.List[tuple[int, int, int]] = []
        self.seed_at_l1 = seed_at_l1
        self.seed_at_l2 = seed_at_l2

    def get_key(
        self,
        target_sd: bytes,
        root_key_identifier: t.Optional[uuid.UUID],
        l0: int,
        l1: int,
        l2: int,
    ) -> gkdi.GroupKeyEnvelope:
        assert root_key_identifier
        self.calls.append((l0, l1, l2))
        return self.cache._get_key(
            target_sd,
            root_key_identifier,
            l0,
            self.seed_at_l1 if self.seed_at_l1 >= 0 else l1,
            self.seed_at_l2 if self.seed_at_l2 >= 0 else l2,
        )


class _AsyncProvider(_LocalProvider):
    async def async_get_key(
        self,
        target_sd: bytes,
        root_key_identifier: t.Optional[uuid.UUID],
        l0: int,
        l1: int,
        l2: int,
    ) -> gkdi.GroupKeyEnvelope:
        return self.get_key(target_sd, root_key_identifier, l0, l1, l2)


def _assert_blob_round_trip(
    blob: bytes,
    provider: dpapi_ng.KeyProvider,
    expected: bytes,
) -> None:
    unpacked = client.DPAPINGBlob.unpack(blob)
    assert dpapi_ng.ncrypt_unprotect_secret(blob, key_provider=provider) == expected
    assert unpacked.key_identifier.l0 == _fixed_time().l0


def test_protect_sync_and_async_provider_same_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_data = b"same-key-source"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    _set_fixed_time(monkeypatch)

    cache = _load_root_key("kdf_sha512_nonce")[1]
    root_key_id = list(cache._root_keys.keys())[0]
    sync_provider = _LocalProvider(cache)

    sync_blob = dpapi_ng.ncrypt_protect_secret(
        test_data,
        test_protection_descriptor,
        root_key_identifier=root_key_id,
        key_provider=sync_provider,
    )

    async_provider = _AsyncProvider(cache)
    async_blob = asyncio.run(
        dpapi_ng.async_ncrypt_protect_secret(
            test_data,
            test_protection_descriptor,
            root_key_identifier=root_key_id,
            key_provider=async_provider,
        )
    )

    sync_unpacked = client.DPAPINGBlob.unpack(sync_blob)
    async_unpacked = client.DPAPINGBlob.unpack(async_blob)

    indices = _fixed_time()
    assert sync_provider.calls == async_provider.calls == [(indices.l0, indices.l1, indices.l2)]
    assert (
        sync_unpacked.key_identifier.l0,
        sync_unpacked.key_identifier.l1,
        sync_unpacked.key_identifier.l2,
    ) == (
        async_unpacked.key_identifier.l0,
        async_unpacked.key_identifier.l1,
        async_unpacked.key_identifier.l2,
    ) == (indices.l0, indices.l1, indices.l2)
    assert sync_unpacked.key_identifier.root_key_identifier == root_key_id
    assert async_unpacked.key_identifier.root_key_identifier == root_key_id
    assert sync_unpacked.protection_descriptor == async_unpacked.protection_descriptor

    # The CEK is randomly generated so the blobs differ, but both must
    # decrypt with the same offline provider.
    _assert_blob_round_trip(sync_blob, sync_provider, test_data)
    _assert_blob_round_trip(async_blob, async_provider, test_data)


def test_protect_async_provider_crosses_time_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_data = b"boundary"
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    _set_fixed_time(monkeypatch)
    indices = _fixed_time()

    cache = _load_root_key("kdf_sha256_nonce")[1]
    root_key_id = list(cache._root_keys.keys())[0]
    provider = _LocalProvider(cache)

    class _CrossingProvider(dpapi_ng.KeyProvider):
        async def async_get_key(
            self,
            target_sd: bytes,
            root_key_identifier: t.Optional[uuid.UUID],
            l0: int,
            l1: int,
            l2: int,
        ) -> gkdi.GroupKeyEnvelope:
            gke = provider.get_key(target_sd, root_key_identifier, l0, l1, l2)
            # Move the clock past the boundary while the provider was
            # waiting. The protect operation must not resample.
            monkeypatch.setattr(
                client,
                "_get_current_time",
                lambda: (indices.l2 + 1) * client._TIME_SLOT
                + indices.l1 * client._L1_TIME_SLOT
                + indices.l0 * client._L0_TIME_SLOT,
            )
            return gke

    crossing = _CrossingProvider()
    blob = asyncio.run(
        dpapi_ng.async_ncrypt_protect_secret(
            test_data,
            test_protection_descriptor,
            root_key_identifier=root_key_id,
            key_provider=crossing,
        )
    )

    unpacked = client.DPAPINGBlob.unpack(blob)
    assert (unpacked.key_identifier.l0, unpacked.key_identifier.l1, unpacked.key_identifier.l2) == (
        indices.l0,
        indices.l1,
        indices.l2,
    )
    assert provider.calls == [(indices.l0, indices.l1, indices.l2)]

    # Verify the key identifier refers to the material actually used. The
    # KEK derived from the envelope at those indices must match an
    # independent derivation from the raw seed at the higher index.
    raw_gke = cache._get_key(
        unpacked.protection_descriptor.get_target_sd(),
        root_key_id,
        indices.l0,
        31,
        31,
    )
    assert raw_gke
    kdf_parameters = gkdi.KDFParameters.unpack(raw_gke.kdf_parameters)
    _, l2_key = gkdi.compute_l1_l2_key(
        kdf_parameters.hash_algorithm,
        indices.l1,
        indices.l2,
        raw_gke,
    )
    current_gke = cache._get_key(
        unpacked.protection_descriptor.get_target_sd(),
        root_key_id,
        indices.l0,
        indices.l1,
        indices.l2,
    )
    assert current_gke
    expected_kek = gkdi.kdf(
        kdf_parameters.hash_algorithm,
        l2_key,
        gkdi.KDS_SERVICE_LABEL,
        unpacked.key_identifier.key_info,
        32,
    )
    assert current_gke.get_kek(unpacked.key_identifier) == expected_kek
    assert dpapi_ng.ncrypt_unprotect_secret(blob, key_provider=provider) == test_data


@pytest.mark.parametrize(
    "public",
    [True, False],
)
def test_protect_provider_rejects_unusable_envelope(
    public: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    _set_fixed_time(monkeypatch)

    cache = _load_root_key("kdf_sha512_nonce")[1]
    root_key_id = list(cache._root_keys.keys())[0]

    class _RejectingProvider(dpapi_ng.KeyProvider):
        def get_key(
            self,
            target_sd: bytes,
            root_key_identifier: t.Optional[uuid.UUID],
            l0: int,
            l1: int,
            l2: int,
        ) -> gkdi.GroupKeyEnvelope:
            gke = cache._get_key(target_sd, root_key_identifier, l0, l1, l2)
            assert gke
            if public:
                return dataclasses.replace(gke, flags=1, l2_key=os.urandom(32))
            else:
                # A seed below the requested L2 index cannot derive it.
                return dataclasses.replace(gke, l1=l1, l2=l2 - 1, l2_key=b"")

    with pytest.raises(ValueError, match="Key provider"):
        dpapi_ng.ncrypt_protect_secret(
            b"x",
            test_protection_descriptor,
            root_key_identifier=root_key_id,
            key_provider=_RejectingProvider(),
        )


def test_protect_async_provider_cancel_does_not_return_blob(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_protection_descriptor = "S-1-5-21-2185496602-3367037166-1388177638-1103"
    _set_fixed_time(monkeypatch)

    cache = _load_root_key("kdf_sha512_nonce")[1]
    root_key_id = list(cache._root_keys.keys())[0]

    class _SlowProvider(dpapi_ng.KeyProvider):
        cancelled = False

        async def async_get_key(
            self,
            target_sd: bytes,
            root_key_identifier: t.Optional[uuid.UUID],
            l0: int,
            l1: int,
            l2: int,
        ) -> gkdi.GroupKeyEnvelope:
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                self.cancelled = True
                raise

            raise AssertionError("provider should have been cancelled")

    async def _run() -> None:
        provider = _SlowProvider()
        task = asyncio.create_task(
            dpapi_ng.async_ncrypt_protect_secret(
                b"x",
                test_protection_descriptor,
                root_key_identifier=root_key_id,
                key_provider=provider,
            )
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert provider.cancelled

    asyncio.run(_run())

