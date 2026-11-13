# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
import uuid

from ._rpc import SyntaxId

EPM = SyntaxId(uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)

# https://pubs.opengroup.org/onlinepubs/9629399/apdxl.htm
# https://pubs.opengroup.org/onlinepubs/9629399/apdxi.htm#tagcjh_28


class FloorProtocol(enum.IntEnum):
    OSI = 0x00
    DNA_SESSION_CONTROL = 0x02
    DNA_SESSION_CONTROL_V3 = 0x03
    DNA_NSP_TRANSPORT = 0x04
    TP4 = 0x05
    CLNS = 0x06
    TCP = 0x07
    UDP = 0x08
    IP = 0x09
    RPC_CONNECTIONLESS = 0x0A
    RPC_CONNECTION_ORIENTED = 0x0B
    UUID_ID = 0x0D
    NAMED_PIPES = 0x10
    NETBIOS = 0x11
    NETBEUI = 0x12
    NETWARE_SPX = 0x13
    NETWARE_IPX = 0x14
    APPLETALK_STREAM = 0x16
    APPLETALK_DATARAM = 0x17
    APPLETALK = 0x18
    NETBIOS2 = 0x19
    VINES_SPP = 0x1A
    VINES_IPC = 0x1B
    STREET_TALK = 0x1C
    UNIX_DOMAIN_SOCKET = 0x20
    NULL = 0x21
    NETBIOS3 = 0x22

    @classmethod
    def _missing_(cls, value: object) -> t.Optional[enum.Enum]:
        new_member = int.__new__(cls, t.cast(int, value))
        new_member._name_ = f"FloorProtocol Unknown 0x{value:04X}"
        new_member._value_ = value  # type: ignore[assignment]
        return cls._value2member_map_.setdefault(value, new_member)


@dataclasses.dataclass(frozen=True)
class Floor:
    protocol: FloorProtocol
    lhs: bytes
    rhs: bytes

    def pack(self) -> bytes:
        return b"".join(
            [
                (len(self.lhs) + 1).to_bytes(2, byteorder="little"),
                self.protocol.to_bytes(1, byteorder="little"),
                self.lhs,
                len(self.rhs).to_bytes(2, byteorder="little"),
                self.rhs,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> Floor:
        view = memoryview(data)

        lhs_len = int.from_bytes(view[:2], byteorder="little")
        proto = FloorProtocol(view[2])
        lhs = view[3 : lhs_len + 2].tobytes()
        offset = lhs_len + 2

        rhs_len = int.from_bytes(view[offset : offset + 2], byteorder="little")
        rhs = view[offset + 2 : offset + rhs_len + 2].tobytes()

        unpack_func = _FLOOR_TYPE_REGISTRY.get(proto, None)
        if unpack_func:
            floor = unpack_func(lhs, rhs)
            object.__setattr__(floor, "lhs", lhs)
            object.__setattr__(floor, "rhs", rhs)
            return floor

        else:
            return cls(protocol=proto, lhs=lhs, rhs=rhs)


T = t.TypeVar("T")
_FLOOR_TYPE_REGISTRY: t.Dict[FloorProtocol, t.Callable[[bytes, bytes], Floor]] = {}


def register_floor(cls: T) -> T:
    _FLOOR_TYPE_REGISTRY[getattr(cls, "protocol").default] = getattr(cls, "_unpack")
    return cls


@dataclasses.dataclass(frozen=True)
class _KnownFloor(Floor):
    lhs: bytes = dataclasses.field(init=False, repr=False, default=b"")
    rhs: bytes = dataclasses.field(init=False, repr=False, default=b"")


@dataclasses.dataclass(frozen=True)
@register_floor
class TCPFloor(_KnownFloor):
    protocol: FloorProtocol = dataclasses.field(init=False, default=FloorProtocol.TCP)
    port: int

    def pack(self) -> bytes:
        return Floor(self.protocol, b"", self.port.to_bytes(2, byteorder="big")).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> TCPFloor:
        return TCPFloor(int.from_bytes(rhs, byteorder="big"))


@dataclasses.dataclass(frozen=True)
@register_floor
class IPFloor(_KnownFloor):
    protocol: FloorProtocol = dataclasses.field(init=False, default=FloorProtocol.IP)
    addr: int

    def pack(self) -> bytes:
        return Floor(self.protocol, b"", self.addr.to_bytes(4, byteorder="big")).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> IPFloor:
        return IPFloor(int.from_bytes(rhs, byteorder="big"))


@dataclasses.dataclass(frozen=True)
@register_floor
class RPCConnectionOrientedFloor(_KnownFloor):
    protocol: FloorProtocol = dataclasses.field(init=False, default=FloorProtocol.RPC_CONNECTION_ORIENTED)
    version_minor: int

    def pack(self) -> bytes:
        return Floor(self.protocol, b"", self.version_minor.to_bytes(2, byteorder="little")).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> RPCConnectionOrientedFloor:
        return RPCConnectionOrientedFloor(int.from_bytes(rhs, byteorder="little"))


@dataclasses.dataclass(frozen=True)
@register_floor
class UUIDFloor(_KnownFloor):
    protocol: FloorProtocol = dataclasses.field(init=False, default=FloorProtocol.UUID_ID)
    uuid: uuid.UUID
    version: int
    version_minor: int

    def pack(self) -> bytes:
        return Floor(
            protocol=self.protocol,
            lhs=self.uuid.bytes_le + self.version.to_bytes(2, byteorder="little"),
            rhs=self.version_minor.to_bytes(2, byteorder="little"),
        ).pack()

    @classmethod
    def _unpack(
        cls,
        lhs: bytes,
        rhs: bytes,
    ) -> UUIDFloor:
        object_uuid = uuid.UUID(bytes_le=lhs[:16])
        version = int.from_bytes(lhs[16:18], byteorder="little")
        version_minor = int.from_bytes(rhs, byteorder="little")

        return UUIDFloor(object_uuid, version, version_minor)


def build_tcpip_tower(
    service: SyntaxId,
    data_rep: SyntaxId,
    port: int,
    addr: int,
) -> t.List[Floor]:
    return [
        UUIDFloor(service.uuid, service.version, service.version_minor),
        UUIDFloor(data_rep.uuid, data_rep.version, data_rep.version_minor),
        RPCConnectionOrientedFloor(0),
        TCPFloor(port),
        IPFloor(addr),
    ]


class EpmEndpointError(ValueError):
    """No usable TCP endpoint could be selected from an ept_map response.

    The reason categories exposed by this exception are safe to report to a
    caller. They identify the shape of the rejected response without including
    server supplied addresses or raw tower data.
    """

    def __init__(
        self,
        reason: str,
        tower_rejections: t.Sequence[tuple[int, str]] = (),
    ) -> None:
        self.reason = reason
        self.tower_rejections = tuple(tower_rejections)

        message = f"Did not find a usable TCP endpoint in ept_map response ({reason})"
        if self.tower_rejections:
            rejected = ", ".join(f"tower {i}: {r}" for i, r in self.tower_rejections)
            message += f"; rejected candidates: {rejected}"

        super().__init__(message)


@dataclasses.dataclass(frozen=True)
class TcpEndpoint:
    # The address floor is deliberately omitted. Endpoint Mapper responses
    # describe an endpoint but they must not change the host that the caller
    # selected for authentication.
    port: int
    transfer_syntax: SyntaxId


def _reject(reason: str) -> None:
    raise _TowerRejected(reason)


class _TowerRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _floor_rejection(floor: Floor, expected: str) -> str:
    if type(floor) is not Floor:
        # Use a stable, snake case name rather than the class name so the
        # reported reason is predictable and safe to expose.
        class_names: t.Dict[type, str] = {
            TCPFloor: "tcp",
            IPFloor: "ip",
            RPCConnectionOrientedFloor: "rpc_connection_oriented",
            UUIDFloor: "uuid",
        }
        name = class_names.get(type(floor), "unsupported_floor")
        return f"unexpected_{name}_floor_where_{expected}_expected"

    protocol = floor.protocol
    if protocol.name.startswith("FloorProtocol Unknown"):
        return f"unknown_floor_0x{int(protocol):02X}"

    if expected == "tcp" and protocol == FloorProtocol.TCP:
        # A TCP floor that could not be decoded as a TCPFloor has a malformed
        # or truncated payload.
        return "truncated_port"

    return f"unexpected_{protocol.name.lower()}_floor_where_{expected}_expected"


def _check_payload(value: bytes, expected_length: int) -> None:
    # Floors constructed directly from their dataclasses have no raw payload
    # until they have been packed and unpacked. Only enforce the length when a
    # payload was present in the response.
    if value and len(value) != expected_length:
        _reject("truncated_floor_payload")


def _validate_tcp_tower(
    tower: t.List[Floor],
    interface: SyntaxId,
    transfer_syntaxes: t.Sequence[SyntaxId],
) -> TcpEndpoint:
    if len(tower) < 4 or len(tower) > 5:
        _reject("invalid_floor_count")

    unknown_floor = next(
        (f for f in tower if type(f) is Floor and f.protocol.name.startswith("FloorProtocol Unknown")),
        None,
    )
    if unknown_floor is not None:
        # Unknown floors cannot participate in ordered matching, even if the
        # rest of the tower happens to look usable.
        _reject(_floor_rejection(unknown_floor, "floor"))

    interface_floor = tower[0]
    if not isinstance(interface_floor, UUIDFloor):
        _reject(_floor_rejection(interface_floor, "interface_uuid"))

    _check_payload(interface_floor.lhs, 18)
    _check_payload(interface_floor.rhs, 2)
    syntax = SyntaxId(interface_floor.uuid, interface_floor.version, interface_floor.version_minor)
    if syntax != interface:
        _reject("interface_mismatch")

    transfer_floor = tower[1]
    if not isinstance(transfer_floor, UUIDFloor):
        _reject(_floor_rejection(transfer_floor, "transfer_syntax_uuid"))

    _check_payload(transfer_floor.lhs, 18)
    _check_payload(transfer_floor.rhs, 2)
    transfer_syntax = SyntaxId(transfer_floor.uuid, transfer_floor.version, transfer_floor.version_minor)
    if transfer_syntax not in transfer_syntaxes:
        _reject("transfer_syntax_mismatch")

    connection_floor = tower[2]
    if not isinstance(connection_floor, RPCConnectionOrientedFloor):
        _reject(_floor_rejection(connection_floor, "rpc_connection_oriented"))

    _check_payload(connection_floor.rhs, 2)
    if connection_floor.version_minor != 0:
        _reject("unsupported_connection_oriented_version")

    tcp_floor = tower[3]
    if not isinstance(tcp_floor, TCPFloor):
        _reject(_floor_rejection(tcp_floor, "tcp"))

    # An empty rhs is used by a locally constructed TCPFloor; packed responses
    # always contain exactly two bytes. One byte means the port was truncated
    # and more than two means it was not a valid TCP endpoint.
    if len(tcp_floor.rhs) == 1:
        _reject("truncated_port")
    if len(tcp_floor.rhs) > 2:
        _reject("invalid_port")
    if tcp_floor.port < 1 or tcp_floor.port > 0xFFFF:
        _reject("invalid_port")

    if len(tower) == 5:
        address_floor = tower[4]
        if not isinstance(address_floor, IPFloor):
            _reject(_floor_rejection(address_floor, "ip"))

        _check_payload(address_floor.rhs, 4)

    return TcpEndpoint(port=tcp_floor.port, transfer_syntax=transfer_syntax)


def select_tcp_endpoint(
    towers: t.Iterable[t.List[Floor]],
    interface: SyntaxId,
    transfer_syntaxes: t.Sequence[SyntaxId],
) -> TcpEndpoint:
    """Select a TCP endpoint for an RPC interface from EPM towers.

    Every tower is checked independently. A tower is only usable when it
    contains, in order, the expected interface UUID/version, an accepted
    transfer syntax, an RPC connection-oriented floor, a TCP floor with a
    complete two byte port, and optionally an IP floor. Unknown or otherwise
    unsupported floors cause the whole tower to be rejected rather than allowing
    a later floor to be used by accident.

    The selected endpoint never contains the address from the IP floor. The
    caller remains responsible for the target host so an EPM response cannot
    redirect authentication to a different domain controller.

    Args:
        towers: The towers returned by ``ept_map``.
        interface: The RPC interface UUID and version that must be present.
        transfer_syntaxes: Accepted transfer syntaxes in preference order.

    Returns:
        TcpEndpoint: The selected port and transfer syntax.

    Raises:
        EpmEndpointError: No tower matched the requested interface and
            transport.
    """

    candidates: t.List[tuple[int, TcpEndpoint]] = []
    rejections: t.List[tuple[int, str]] = []

    for idx, tower in enumerate(towers):
        try:
            endpoint = _validate_tcp_tower(list(tower), interface, transfer_syntaxes)
        except _TowerRejected as e:
            rejections.append((idx, e.reason))
        else:
            preference = transfer_syntaxes.index(endpoint.transfer_syntax)
            candidates.append((preference, endpoint))

    if not candidates:
        raise EpmEndpointError("no_matching_tower", rejections)

    # Preference is explicit and the port is a deterministic tie breaker. The
    # selection therefore does not depend on the order of the towers in the
    # response.
    candidates.sort(key=lambda c: (c[0], c[1].port))
    return candidates[0][1]


@dataclasses.dataclass(frozen=True)
class EptMap:
    opnum: int = dataclasses.field(init=False, repr=False, default=3)

    obj: t.Optional[uuid.UUID]
    tower: t.List[Floor]
    entry_handle: t.Optional[tuple[int, uuid.UUID]]
    max_towers: int

    # MS-RPCE 2.2.1.2.5 ept_map Method
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791
    # void ept_map(
    #     [in] handle_t hEpMapper,
    #     [in, ptr] UUID* obj,
    #     [in, ptr] twr_p_t map_tower,
    #     [in, out] ept_lookup_handle_t* entry_handle,
    #     [in, range(0,500)] unsigned long max_towers,
    #     [out] unsigned long* num_towers,
    #     [out, ptr, size_is(max_towers), length_is(*num_towers)]
    #         twr_p_t* ITowers,
    #     [out] error_status* status
    # );

    def pack(self) -> bytes:
        b_tower = b"".join(
            [
                len(self.tower).to_bytes(2, byteorder="little"),
                b"".join(f.pack() for f in self.tower),
            ]
        )
        tower_padding = -(len(b_tower) + 4) % 8

        if self.entry_handle:
            b_entry_handle = self.entry_handle[0].to_bytes(4, byteorder="little") + self.entry_handle[1].bytes_le
        else:
            b_entry_handle = b"\x00" * 20

        return b"".join(
            [
                # obj with a referent id of 1
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
                self.obj.bytes_le if self.obj else b"\x00" * 16,
                # Tower referent id 2
                b"\x02\x00\x00\x00\x00\x00\x00\x00",
                len(b_tower).to_bytes(8, byteorder="little"),
                len(b_tower).to_bytes(4, byteorder="little"),
                b_tower,
                b"\x00" * tower_padding,
                b_entry_handle,
                self.max_towers.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EptMap:
        view = memoryview(data)

        b_obj = view[8:24].tobytes()
        if b_obj == b"\x00" * 16:
            obj = None
        else:
            obj = uuid.UUID(bytes_le=b_obj)

        view = view[32:]

        tower_length = int.from_bytes(view[:8], byteorder="little")
        padding = -(tower_length + 4) % 8

        floor_len = int.from_bytes(view[12:14], byteorder="little")
        view = view[14:]

        tower = []
        for _ in range(floor_len):
            floor = Floor.unpack(view)
            view = view[len(floor.lhs) + len(floor.rhs) + 5 :]
            tower.append(floor)

        view = view[padding:]

        b_entry_handle = view[:20].tobytes()
        if b_entry_handle == b"\x00" * 20:
            entry_handle = None
        else:
            entry_handle = (
                int.from_bytes(view[:4], byteorder="little"),
                uuid.UUID(bytes_le=view[4:20].tobytes()),
            )

        max_towers = int.from_bytes(view[20:24], byteorder="little")

        return cls(
            obj=obj,
            tower=tower,
            entry_handle=entry_handle,
            max_towers=max_towers,
        )


@dataclasses.dataclass(frozen=True)
class EptMapResult:
    entry_handle: t.Optional[tuple[int, uuid.UUID]]
    towers: t.List[t.List[Floor]]
    status: int

    def pack(self) -> bytes:
        if self.entry_handle:
            b_entry_handle = self.entry_handle[0].to_bytes(4, byteorder="little") + self.entry_handle[1].bytes_le
        else:
            b_entry_handle = b"\x00" * 20

        b_tower_referents = bytearray()
        b_tower = bytearray()
        for idx, t in enumerate(self.towers):
            b_tower_referents += (idx + 3).to_bytes(8, byteorder="little")

            b_t = b"".join(
                [
                    len(t).to_bytes(2, byteorder="little"),
                    b"".join(f.pack() for f in t),
                ]
            )
            padding = -(len(b_t)) % 4
            b_tower += b"".join(
                [
                    len(b_t).to_bytes(8, byteorder="little"),
                    len(b_t).to_bytes(4, byteorder="little"),
                    b_t,
                    b"\x00" * padding,
                ]
            )

        return b"".join(
            [
                b_entry_handle,
                len(self.towers).to_bytes(4, byteorder="little"),
                len(self.towers).to_bytes(8, byteorder="little"),
                b"\x00" * 8,  # Tower pointer offset
                len(self.towers).to_bytes(8, byteorder="little"),
                b_tower_referents,
                b_tower,
                self.status.to_bytes(4, byteorder="little"),
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EptMapResult:
        view = memoryview(data)
        if len(view) < 48:
            raise ValueError("Truncated ept_map response")

        status = int.from_bytes(view[-4:], byteorder="little")
        b_entry_handle = view[:20].tobytes()
        if b_entry_handle == b"\x00" * 20:
            entry_handle = None
        else:
            entry_handle = (
                int.from_bytes(view[:4], byteorder="little"),
                uuid.UUID(bytes_le=view[4:20].tobytes()),
            )

        # num_towers = int.from_bytes(view[20:24], byteorder="little")
        # max_tower_count = int.from_bytes(view[24:32], byteorder="little")
        # tower_offset = int.from_bytes(view[32:40], byteorder="little")
        tower_count = int.from_bytes(view[40:48], byteorder="little")
        tower_data_offset = 8 * tower_count  # Ignore referent ids
        if len(view) < 48 + tower_data_offset + 4:
            raise ValueError("Truncated ept_map tower array")

        view = view[48 + tower_data_offset :]

        towers: t.List[t.List[Floor]] = []
        for _ in range(tower_count):
            if len(view) < 14:
                raise ValueError("Truncated ept_map tower header")

            tower_length = int.from_bytes(view[:8], byteorder="little")
            padding = -(tower_length + 4) % 8

            floor_len = int.from_bytes(view[12:14], byteorder="little")
            view = view[14:]

            tower = []
            for _ in range(floor_len):
                floor = Floor.unpack(view)
                view = view[len(floor.lhs) + len(floor.rhs) + 5 :]
                tower.append(floor)

            towers.append(tower)
            view = view[padding:]

        return cls(
            entry_handle=entry_handle,
            towers=towers,
            status=status,
        )
