# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

import pytest

import dpapi_ng._rpc as rpc
from dpapi_ng import _epm as epm

SERVICE = rpc.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
DATA_REP = rpc.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = rpc.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)
OTHER_INTERFACE = rpc.SyntaxId(uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00"), 1, 0)


def test_ept_map_pack() -> None:
    expected = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\x00\x87\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x04\x00\x00\x00"
    )
    service = rpc.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
    data_rep = rpc.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)

    msg = epm.EptMap(
        obj=None,
        tower=epm.build_tcpip_tower(service, data_rep, 135, 0),
        entry_handle=None,
        max_towers=4,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_unpack() -> None:
    data = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\x00\x87\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x04\x00\x00\x00"
    )
    resp = epm.EptMap.unpack(data)
    assert isinstance(resp, epm.EptMap)
    assert resp.obj is None
    assert len(resp.tower) == 5
    assert isinstance(resp.tower[0], epm.UUIDFloor)
    assert resp.tower[0].uuid == uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085")
    assert resp.tower[0].version == 1
    assert resp.tower[0].version_minor == 0
    assert resp.tower[0].protocol == epm.FloorProtocol.UUID_ID
    assert resp.tower[0].lhs
    assert resp.tower[0].rhs
    assert isinstance(resp.tower[1], epm.UUIDFloor)
    assert resp.tower[1].uuid == uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
    assert resp.tower[1].version == 2
    assert resp.tower[1].version_minor == 0
    assert resp.tower[1].protocol == epm.FloorProtocol.UUID_ID
    assert resp.tower[1].lhs
    assert resp.tower[1].rhs
    assert isinstance(resp.tower[2], epm.RPCConnectionOrientedFloor)
    assert resp.tower[2].version_minor == 0
    assert resp.tower[2].protocol == epm.FloorProtocol.RPC_CONNECTION_ORIENTED
    assert resp.tower[2].lhs == b""
    assert resp.tower[2].rhs
    assert isinstance(resp.tower[3], epm.TCPFloor)
    assert resp.tower[3].port == 135
    assert resp.tower[3].protocol == epm.FloorProtocol.TCP
    assert resp.tower[3].lhs == b""
    assert resp.tower[3].rhs
    assert isinstance(resp.tower[4], epm.IPFloor)
    assert resp.tower[4].addr == 0
    assert resp.tower[4].protocol == epm.FloorProtocol.IP
    assert resp.tower[4].lhs == b""
    assert resp.tower[4].rhs
    assert resp.entry_handle is None
    assert resp.max_towers == 4


def test_ept_map_pack_obj_and_entry_handle() -> None:
    expected = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x90\x80\x92\xbc\x6f\x40"
        b"\xbf\xbb\xb2\xdc\xd4\xa7\x26\xee"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x01\x00\x01\x00"
        b"\x0b\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x50\x62\x62\xea"
        b"\x2f\x27\xb2\x4a\x88\xa7\x8a\xbe"
        b"\x11\x40\x37\x24\x01\x00\x00\x00"
    )

    msg = epm.EptMap(
        obj=uuid.UUID("80900533-bc92-406f-bfbb-b2dcd4a726ee"),
        tower=[epm.RPCConnectionOrientedFloor(0)],
        entry_handle=(0, uuid.UUID("ea626250-272f-4ab2-88a7-8abe11403724")),
        max_towers=1,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_unpack_obj_and_entry_handle() -> None:
    data = (
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x33\x05\x90\x80\x92\xbc\x6f\x40"
        b"\xbf\xbb\xb2\xdc\xd4\xa7\x26\xee"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x00\x00\x00\x00"
        b"\x09\x00\x00\x00\x01\x00\x01\x00"
        b"\x0b\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x50\x62\x62\xea"
        b"\x2f\x27\xb2\x4a\x88\xa7\x8a\xbe"
        b"\x11\x40\x37\x24\x01\x00\x00\x00"
    )
    resp = epm.EptMap.unpack(data)
    assert isinstance(resp, epm.EptMap)
    assert resp.obj == uuid.UUID("80900533-bc92-406f-bfbb-b2dcd4a726ee")
    assert len(resp.tower) == 1
    assert isinstance(resp.tower[0], epm.RPCConnectionOrientedFloor)
    assert resp.tower[0].version_minor == 0
    assert resp.tower[0].protocol == epm.FloorProtocol.RPC_CONNECTION_ORIENTED
    assert resp.tower[0].lhs == b""
    assert resp.tower[0].rhs
    assert resp.entry_handle == (0, uuid.UUID("ea626250-272f-4ab2-88a7-8abe11403724"))
    assert resp.max_towers == 1


def test_ept_map_result_pack() -> None:
    expected = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x03\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x05\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x08\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x06\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x03\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    service = rpc.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
    data_rep = rpc.SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)

    msg = epm.EptMapResult(
        entry_handle=None,
        towers=[
            epm.build_tcpip_tower(service, data_rep, 49672, 0),
            epm.build_tcpip_tower(service, data_rep, 49670, 0),
            epm.build_tcpip_tower(service, data_rep, 49667, 0),
        ],
        status=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_result_unpack() -> None:
    data = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x03\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00\x00\x00\x00"
        b"\x04\x00\x00\x00\x00\x00\x00\x00"
        b"\x05\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x08\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x06\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x00\x00\x00\x00"
        b"\x4b\x00\x00\x00\x05\x00\x13\x00"
        b"\x0d\x60\x59\x78\xb9\x4f\x52\xdf"
        b"\x11\x8b\x6d\x83\xdc\xde\xd7\x20"
        b"\x85\x01\x00\x02\x00\x00\x00\x13"
        b"\x00\x0d\x04\x5d\x88\x8a\xeb\x1c"
        b"\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        b"\x48\x60\x02\x00\x02\x00\x00\x00"
        b"\x01\x00\x0b\x02\x00\x00\x00\x01"
        b"\x00\x07\x02\x00\xc2\x03\x01\x00"
        b"\x09\x04\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    resp = epm.EptMapResult.unpack(data)
    assert isinstance(resp, epm.EptMapResult)
    assert resp.entry_handle is None
    assert len(resp.towers) == 3

    for idx, port in enumerate([49672, 49670, 49667]):
        floors = resp.towers[idx]

        assert len(floors) == 5
        assert isinstance(floors[0], epm.UUIDFloor)
        assert floors[0].uuid == uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085")
        assert floors[0].version == 1
        assert floors[0].version_minor == 0
        assert floors[0].protocol == epm.FloorProtocol.UUID_ID
        assert floors[0].lhs
        assert floors[0].rhs
        assert isinstance(floors[1], epm.UUIDFloor)
        assert floors[1].uuid == uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
        assert floors[1].version == 2
        assert floors[1].version_minor == 0
        assert floors[1].protocol == epm.FloorProtocol.UUID_ID
        assert floors[1].lhs
        assert floors[1].rhs
        assert isinstance(floors[2], epm.RPCConnectionOrientedFloor)
        assert floors[2].version_minor == 0
        assert floors[2].protocol == epm.FloorProtocol.RPC_CONNECTION_ORIENTED
        assert floors[2].lhs == b""
        assert floors[2].rhs
        assert isinstance(floors[3], epm.TCPFloor)
        assert floors[3].port == port
        assert floors[3].protocol == epm.FloorProtocol.TCP
        assert floors[3].lhs == b""
        assert floors[3].rhs
        assert isinstance(floors[4], epm.IPFloor)
        assert floors[4].addr == 0
        assert floors[4].protocol == epm.FloorProtocol.IP
        assert floors[4].lhs == b""
        assert floors[4].rhs


def test_ept_map_result_pack_handle() -> None:
    expected = (
        b"\x00\x00\x00\x00\xc9\x53\xc3\x6b"
        b"\xe9\x11\xaa\x47\xb6\xfd\x13\x8d"
        b"\x04\xda\x08\x9d\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    msg = epm.EptMapResult(
        entry_handle=(0, uuid.UUID("6bc353c9-11e9-47aa-b6fd-138d04da089d")),
        towers=[],
        status=0,
    )
    actual = msg.pack()
    assert actual == expected


def test_ept_map_result_unpack_handle() -> None:
    data = (
        b"\x00\x00\x00\x00\xc9\x53\xc3\x6b"
        b"\xe9\x11\xaa\x47\xb6\xfd\x13\x8d"
        b"\x04\xda\x08\x9d\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    resp = epm.EptMapResult.unpack(data)
    assert isinstance(resp, epm.EptMapResult)
    assert resp.entry_handle == (0, uuid.UUID("6bc353c9-11e9-47aa-b6fd-138d04da089d"))
    assert len(resp.towers) == 0


def test_unpack_unknown_floor() -> None:
    data = b"\x02\x00\xFF\x00\x01\x00\x00"

    msg = epm.Floor.unpack(data)

    assert msg.protocol == epm.FloorProtocol(0xFF)
    assert msg.lhs == b"\x00"
    assert msg.rhs == b"\x00"


def _make_response(stub_data: bytes) -> rpc.Response:
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


def _map_result_response(towers: t.List[t.List[epm.Floor]]) -> rpc.Response:
    return _make_response(epm.EptMapResult(entry_handle=None, towers=towers, status=0).pack())


def _roundtrip(towers: t.List[t.List[epm.Floor]]) -> t.List[t.List[epm.Floor]]:
    # Push the towers through the same wire format used by a real response so
    # the decoded floors carry their raw lhs/rhs payloads.
    packed = epm.EptMapResult(entry_handle=None, towers=towers, status=0)
    return epm.EptMapResult.unpack(packed.pack()).towers


def _valid_tower(
    port: int,
    interface: rpc.SyntaxId = SERVICE,
    transfer: rpc.SyntaxId = NDR64,
) -> t.List[epm.Floor]:
    return epm.build_tcpip_tower(interface, transfer, port, 0)


def test_select_tcp_endpoint_order_independent() -> None:
    wrong_interface = _valid_tower(5001, OTHER_INTERFACE)
    wrong_syntax = _valid_tower(5002, SERVICE, DATA_REP)
    valid = _valid_tower(5003)

    orders = [
        [wrong_interface, wrong_syntax, valid],
        [valid, wrong_syntax, wrong_interface],
        [wrong_syntax, valid, wrong_interface],
        [valid, wrong_interface, wrong_syntax],
    ]

    for towers in orders:
        endpoint = epm.select_tcp_endpoint(towers, SERVICE, [NDR64])
        assert endpoint.port == 5003


def test_select_tcp_endpoint_prefers_transfer_syntax() -> None:
    endpoint = epm.select_tcp_endpoint(
        [_valid_tower(5001, SERVICE, DATA_REP), _valid_tower(5002, SERVICE, NDR64)],
        SERVICE,
        [NDR64],
    )
    assert endpoint.port == 5002


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda tower: [epm.UUIDFloor(OTHER_INTERFACE.uuid, 1, 0), *tower[1:]], "interface_mismatch"),
        (
            lambda tower: [tower[0], epm.UUIDFloor(OTHER_INTERFACE.uuid, 1, 0), *tower[2:]],
            "transfer_syntax_mismatch",
        ),
        (
            lambda tower: [tower[0], tower[1], tower[3], tower[2], *tower[4:]],
            "unexpected_tcp_floor_where_rpc_connection_oriented_expected",
        ),
        (
            lambda tower: [tower[0], tower[2], tower[1], tower[3], *tower[4:]],
            "unexpected_rpc_connection_oriented_floor_where_transfer_syntax_uuid_expected",
        ),
        (
            lambda tower: [epm.Floor(epm.FloorProtocol(0xFE), b"", b""), *tower[1:]],
            "unknown_floor_0xFE",
        ),
        (
            lambda tower: [tower[0], epm.Floor(epm.FloorProtocol(0xFE), b"", b""), tower[2], tower[3], tower[4]],
            "unknown_floor_0xFE",
        ),
        (
            lambda tower: [tower[0], tower[1], tower[2]],
            "invalid_floor_count",
        ),
        (
            lambda tower: [*tower[:4], epm.Floor(epm.FloorProtocol.UDP, b"", b"\x00\x00")],
            "unexpected_udp_floor_where_ip_expected",
        ),
        (
            lambda tower: [tower[0], tower[1], tower[2], tower[3], tower[4], tower[4]],
            "invalid_floor_count",
        ),
        (
            lambda tower: [tower[0], tower[1], tower[2], tower[3], epm.TCPFloor(5003)],
            "unexpected_tcp_floor_where_ip_expected",
        ),
        (
            lambda tower: [epm.RPCConnectionOrientedFloor(0), *tower[1:]],
            "unexpected_rpc_connection_oriented_floor_where_interface_uuid_expected",
        ),
    ],
)
def test_select_tcp_endpoint_rejects_tower(
    mutate: t.Callable[[t.List[epm.Floor]], t.List[epm.Floor]],
    reason: str,
) -> None:
    tower = mutate(_valid_tower(5003))

    with pytest.raises(epm.EpmEndpointError) as ctx:
        epm.select_tcp_endpoint([tower], SERVICE, [NDR64])

    assert ctx.value.reason == "no_matching_tower"
    assert ctx.value.tower_rejections == ((0, reason),)


def test_select_tcp_endpoint_rejects_truncated_port() -> None:
    tower = _valid_tower(5003)
    truncated = epm.Floor(epm.FloorProtocol.TCP, b"", b"\x01")
    bad = _roundtrip([[*tower[:3], truncated, tower[4]]])[0]

    # The decoded tower still claims protocol TCP but its rhs is one byte.
    assert len(bad[3].rhs) == 1

    with pytest.raises(epm.EpmEndpointError) as ctx:
        epm.select_tcp_endpoint([bad], SERVICE, [NDR64])

    assert ctx.value.reason == "no_matching_tower"
    assert ctx.value.tower_rejections == ((0, "truncated_port"),)


def test_select_tcp_endpoint_rejects_truncated_uuid_payload() -> None:
    tower = _valid_tower(5003)
    truncated_interface = epm.UUIDFloor(SERVICE.uuid, SERVICE.version, SERVICE.version_minor)
    object.__setattr__(truncated_interface, "lhs", b"\x00" * 10)
    bad = [truncated_interface, *tower[1:]]

    with pytest.raises(epm.EpmEndpointError) as ctx:
        epm.select_tcp_endpoint([bad], SERVICE, [NDR64])

    assert ctx.value.tower_rejections == ((0, "truncated_floor_payload"),)


def test_select_tcp_endpoint_rejects_invalid_port() -> None:
    tower = _valid_tower(5003)

    for port in (0, 0x10000, -1):
        with pytest.raises(epm.EpmEndpointError) as ctx:
            epm.select_tcp_endpoint([[*tower[:3], epm.TCPFloor(port), tower[4]]], SERVICE, [NDR64])

        assert ctx.value.tower_rejections == ((0, "invalid_port"),)


def test_select_tcp_endpoint_all_invalid() -> None:
    wrong_interface = _valid_tower(5001, OTHER_INTERFACE)
    unknown_floor = [
        *_valid_tower(5002)[:2],
        epm.Floor(epm.FloorProtocol(0xFD), b"", b""),
        *_valid_tower(5002)[3:],
    ]

    with pytest.raises(epm.EpmEndpointError) as ctx:
        epm.select_tcp_endpoint([wrong_interface, unknown_floor], SERVICE, [NDR64])

    assert ctx.value.reason == "no_matching_tower"
    assert ctx.value.tower_rejections == ((0, "interface_mismatch"), (1, "unknown_floor_0xFD"))


def test_select_tcp_endpoint_error_is_publicable() -> None:
    error = epm.EpmEndpointError("no_matching_tower", [(0, "interface_mismatch")])

    assert "no_matching_tower" in str(error)
    assert "interface_mismatch" in str(error)
    assert "10." not in str(error)
    assert "dc.example.com" not in str(error)

    # The endpoint carries only the port and syntax, never the IP floor value.
    endpoint = epm.TcpEndpoint(port=5003, transfer_syntax=NDR64)
    assert not hasattr(endpoint, "addr")


def test_client_process_ept_map_result_uses_selection() -> None:
    import dpapi_ng._client as client

    wrong = _roundtrip([_valid_tower(5001, OTHER_INTERFACE)])[0]
    valid = _roundtrip([_valid_tower(5003)])[0]

    response = _map_result_response([wrong, valid])
    assert client._process_ept_map_result(response) == 5003


def test_client_process_ept_map_result_all_invalid() -> None:
    import dpapi_ng._client as client

    wrong = _roundtrip([_valid_tower(5001, OTHER_INTERFACE)])[0]

    with pytest.raises(epm.EpmEndpointError) as ctx:
        client._process_ept_map_result(_map_result_response([wrong]))

    assert ctx.value.reason == "no_matching_tower"
