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
import dpapi_ng._rpc as rpc
from dpapi_ng import _epm as epm

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


class _SecondConnection(Exception):
    def __init__(self, server: str, port: int) -> None:
        super().__init__(server, port)
        self.server = server
        self.port = port


def _ept_map_response(towers: t.List[t.List[epm.Floor]]) -> rpc.Response:
    stub_data = epm.EptMapResult(entry_handle=None, towers=towers, status=0).pack()
    return rpc.Response(
        header=rpc.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=rpc.PacketType.RESPONSE,
            packet_flags=rpc.PacketFlags.PFC_FIRST_FRAG | rpc.PacketFlags.PFC_LAST_FRAG,
            data_rep=rpc.DataRep(),
            frag_len=8 + len(stub_data),
            auth_len=0,
            call_id=2,
        ),
        sec_trailer=None,
        alloc_hint=len(stub_data),
        context_id=0,
        cancel_count=0,
        stub_data=stub_data,
    )


def _accepting_bind_ack(contexts: t.List[rpc.ContextElement]) -> rpc.BindAck:
    return rpc.BindAck(
        header=rpc.PDUHeader(
            version=5,
            version_minor=0,
            packet_type=rpc.PacketType.BIND_ACK,
            packet_flags=rpc.PacketFlags.PFC_FIRST_FRAG | rpc.PacketFlags.PFC_LAST_FRAG,
            data_rep=rpc.DataRep(),
            frag_len=0,
            auth_len=0,
            call_id=2,
        ),
        sec_trailer=None,
        max_xmit_frag=4280,
        max_recv_frag=4280,
        assoc_group=0,
        sec_addr="",
        results=[
            rpc.ContextResult(
                result=rpc.ContextResultCode.ACCEPTANCE,
                reason=0,
                syntax=c.transfer_syntaxes[0].uuid,
                syntax_version=c.transfer_syntaxes[0].version,
            )
            for c in contexts
        ],
    )


class _FakeRpc:
    def __init__(self, ept_response: rpc.Response) -> None:
        self._ept_response = ept_response

    def __enter__(self) -> _FakeRpc:
        return self

    def __exit__(self, *args: t.Any) -> None:
        return None

    def bind(self, contexts: t.List[rpc.ContextElement]) -> rpc.BindAck:
        return _accepting_bind_ack(contexts)

    def request(self, context_id: int, opnum: int, stub_data: bytes, **kwargs: t.Any) -> rpc.Response:
        return self._ept_response


def _run_sync_get_key_with_towers(
    monkeypatch: pytest.MonkeyPatch,
    towers: t.List[t.List[epm.Floor]],
) -> t.List[tuple[str, int]]:
    connections: t.List[tuple[str, int]] = []

    def create_connection(
        server: str,
        port: int = 135,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> _FakeRpc:
        connections.append((server, port))
        if len(connections) == 1:
            return _FakeRpc(_ept_map_response(towers))
        # Do not perform the GKDI call in this transport test, but record the
        # exact host and port the second connection would have used.
        raise _SecondConnection(server, port)

    monkeypatch.setattr(client, "create_rpc_connection", create_connection)

    with pytest.raises(_SecondConnection) as ctx:
        client._sync_get_key("dc.example.com", b"\x00", uuid.uuid4())

    assert ctx.value.server == "dc.example.com"
    assert ctx.value.port != 135
    assert connections == [("dc.example.com", 135), ("dc.example.com", ctx.value.port)]
    return connections


def test_sync_get_key_selects_valid_tower_regardless_of_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_interface = epm.build_tcpip_tower(
        rpc.SyntaxId(uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00"), 1, 0),
        rpc.NDR64,
        5001,
        0,
    )
    wrong_syntax = epm.build_tcpip_tower(client.ISD_KEY, rpc.NDR, 5002, 0)
    valid = epm.build_tcpip_tower(client.ISD_KEY, rpc.NDR64, 5003, 0)

    for towers in (
        [wrong_interface, wrong_syntax, valid],
        [valid, wrong_syntax, wrong_interface],
    ):
        connections = _run_sync_get_key_with_towers(monkeypatch, towers)
        assert connections[1] == ("dc.example.com", 5003)


def test_sync_get_key_all_invalid_towers_make_single_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_interface = epm.build_tcpip_tower(
        rpc.SyntaxId(uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00"), 1, 0),
        rpc.NDR64,
        5001,
        0,
    )
    wrong_syntax = epm.build_tcpip_tower(client.ISD_KEY, rpc.NDR, 5002, 0)

    connections: t.List[tuple[str, int]] = []

    def create_connection(
        server: str,
        port: int = 135,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> _FakeRpc:
        connections.append((server, port))
        return _FakeRpc(_ept_map_response([wrong_interface, wrong_syntax]))

    monkeypatch.setattr(client, "create_rpc_connection", create_connection)

    with pytest.raises(epm.EpmEndpointError) as ctx:
        client._sync_get_key("dc.example.com", b"\x00", uuid.uuid4())

    assert connections == [("dc.example.com", 135)]
    assert ctx.value.reason == "no_matching_tower"
    assert ctx.value.tower_rejections == (
        (0, "interface_mismatch"),
        (1, "transfer_syntax_mismatch"),
    )


def test_sync_get_key_ignores_foreign_address_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The tower advertises a different address but the caller-selected DC
    # identity must still be used for the authenticated connection.
    foreign_addr = 0x0A000001  # 10.0.0.1
    tower = epm.build_tcpip_tower(client.ISD_KEY, rpc.NDR64, 5003, foreign_addr)

    connections = _run_sync_get_key_with_towers(monkeypatch, [tower])

    assert connections == [("dc.example.com", 135), ("dc.example.com", 5003)]


class _FakeAsyncRpc:
    def __init__(self, ept_response: rpc.Response) -> None:
        self._ept_response = ept_response

    async def __aenter__(self) -> _FakeAsyncRpc:
        return self

    async def __aexit__(self, *args: t.Any) -> None:
        return None

    async def bind(self, contexts: t.List[rpc.ContextElement]) -> rpc.BindAck:
        return _accepting_bind_ack(contexts)

    async def request(self, context_id: int, opnum: int, stub_data: bytes, **kwargs: t.Any) -> rpc.Response:
        return self._ept_response


@pytest.mark.asyncio
async def test_async_get_key_all_invalid_towers_make_single_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async_connections: t.List[tuple[str, int]] = []

    async def create_connection(
        server: str,
        port: int = 135,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> _FakeAsyncRpc:
        async_connections.append((server, port))
        towers = [
            epm.build_tcpip_tower(
                rpc.SyntaxId(uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00"), 1, 0),
                rpc.NDR64,
                5001,
                0,
            ),
            epm.build_tcpip_tower(client.ISD_KEY, rpc.NDR, 5002, 0),
        ]
        return _FakeAsyncRpc(_ept_map_response(towers))

    monkeypatch.setattr(client, "async_create_rpc_connection", create_connection)

    with pytest.raises(epm.EpmEndpointError) as ctx:
        await client._async_get_key("dc.example.com", b"\x00", uuid.uuid4())

    assert async_connections == [("dc.example.com", 135)]
    assert ctx.value.reason == "no_matching_tower"


@pytest.mark.asyncio
async def test_async_get_key_uses_selected_port_on_same_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async_connections: t.List[tuple[str, int]] = []

    async def create_connection(
        server: str,
        port: int = 135,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> _FakeAsyncRpc:
        async_connections.append((server, port))
        if len(async_connections) == 1:
            towers = [
                epm.build_tcpip_tower(
                    rpc.SyntaxId(uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00"), 1, 0),
                    rpc.NDR64,
                    5001,
                    0,
                ),
                epm.build_tcpip_tower(client.ISD_KEY, rpc.NDR64, 5003, 0x0A000001),
            ]
            return _FakeAsyncRpc(_ept_map_response(towers))

        raise _SecondConnection(server, port)

    monkeypatch.setattr(client, "async_create_rpc_connection", create_connection)

    with pytest.raises(_SecondConnection) as ctx:
        await client._async_get_key("dc.example.com", b"\x00", uuid.uuid4())

    assert ctx.value.server == "dc.example.com"
    assert ctx.value.port == 5003
    assert async_connections == [("dc.example.com", 135), ("dc.example.com", 5003)]
