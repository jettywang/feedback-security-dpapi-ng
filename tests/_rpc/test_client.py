# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t
import uuid

import pytest
import spnego.iov

from dpapi_ng._rpc import _bind as bind
from dpapi_ng._rpc import _client as client
from dpapi_ng._rpc import _pdu as pdu
from dpapi_ng._rpc import _request as request
from dpapi_ng._rpc import _verification as verification

_ABSTRACT_SYNTAX = bind.SyntaxId(uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
_TRANSFER_SYNTAX = bind.SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)


def _contexts() -> t.List[bind.ContextElement]:
    return [
        bind.ContextElement(
            context_id=0,
            abstract_syntax=_ABSTRACT_SYNTAX,
            transfer_syntaxes=[_TRANSFER_SYNTAX],
        )
    ]


def _pack_with_frag_len(pdu_to_pack: pdu.PDU) -> bytes:
    data = bytearray(pdu_to_pack.pack())
    data[8:10] = len(data).to_bytes(2, byteorder="little")
    return bytes(data)


def _client_verification_trailer() -> verification.VerificationTrailer:
    return verification.VerificationTrailer(
        [
            verification.CommandPContext(
                flags=verification.CommandFlags.SEC_VT_COMMAND_END,
                interface_id=_ABSTRACT_SYNTAX,
                transfer_syntax=_TRANSFER_SYNTAX,
            )
        ]
    )


def _bind_ack(header_signing: bool) -> bytes:
    flags = pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    if header_signing:
        flags |= pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN

    return _pack_with_frag_len(
        bind.BindAck(
            header=pdu.PDUHeader(
                version=5,
                version_minor=0,
                packet_type=pdu.PacketType.BIND_ACK,
                packet_flags=flags,
                data_rep=pdu.DataRep(),
                frag_len=0,
                auth_len=0,
                call_id=1,
            ),
            sec_trailer=None,
            max_xmit_frag=5840,
            max_recv_frag=5840,
            assoc_group=0,
            sec_addr="",
            results=[
                bind.ContextResult(
                    result=bind.ContextResultCode.ACCEPTANCE,
                    reason=0,
                    syntax=_TRANSFER_SYNTAX.uuid,
                    syntax_version=_TRANSFER_SYNTAX.version,
                )
            ],
        )
    )


def _alter_context_response(header_signing: bool) -> bytes:
    flags = pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG
    if header_signing:
        flags |= pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN

    return _pack_with_frag_len(
        bind.AlterContextResponse(
            header=pdu.PDUHeader(
                version=5,
                version_minor=0,
                packet_type=pdu.PacketType.ALTER_CONTEXT_RESP,
                packet_flags=flags,
                data_rep=pdu.DataRep(),
                frag_len=0,
                auth_len=0,
                call_id=1,
            ),
            sec_trailer=None,
            max_xmit_frag=5840,
            max_recv_frag=5840,
            assoc_group=0,
            sec_addr="",
            results=[
                bind.ContextResult(
                    result=bind.ContextResultCode.ACCEPTANCE,
                    reason=0,
                    syntax=_TRANSFER_SYNTAX.uuid,
                    syntax_version=_TRANSFER_SYNTAX.version,
                )
            ],
        )
    )


def _response() -> bytes:
    return _pack_with_frag_len(
        request.Response(
            header=pdu.PDUHeader(
                version=5,
                version_minor=0,
                packet_type=pdu.PacketType.RESPONSE,
                packet_flags=pdu.PacketFlags.PFC_FIRST_FRAG | pdu.PacketFlags.PFC_LAST_FRAG,
                data_rep=pdu.DataRep(),
                frag_len=0,
                auth_len=0,
                call_id=1,
            ),
            sec_trailer=None,
            alloc_hint=0,
            context_id=0,
            cancel_count=0,
            stub_data=b"",
        )
    )


class RecordingAuth:
    """Local authentication double that records the IOV buffer types used."""

    def __init__(
        self,
        complete_after_step: int = 2,
        supports_header_signing: bool = True,
    ) -> None:
        self.complete = False
        self.supports_header_signing = supports_header_signing
        self.last_iov: t.Optional[tuple[spnego.iov.BufferType, spnego.iov.BufferType]] = None
        self.step_count = 0
        self.complete_after_step = complete_after_step
        self.wrap_iov: t.List[tuple[spnego.iov.BufferType, spnego.iov.BufferType]] = []
        self.unwrap_iov: t.List[tuple[spnego.iov.BufferType, spnego.iov.BufferType]] = []

    def step(
        self,
        in_token: t.Optional[bytes] = None,
    ) -> pdu.SecTrailer:
        self.step_count += 1
        if self.step_count >= self.complete_after_step:
            self.complete = True
            value = b""
        else:
            value = f"token{self.step_count}".encode()

        return pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=value,
        )

    def get_empty_trailer(self, pad_length: int) -> pdu.SecTrailer:
        return pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=pad_length,
            context_id=0,
            auth_value=b"\x00" * 16,
        )

    def wrap(
        self,
        header: bytes,
        body: bytes,
        trailer: bytes,
        sign_header: bool,
    ) -> bytes:
        buffer_type = spnego.iov.BufferType.sign_only if sign_header else spnego.iov.BufferType.data_readonly
        self.last_iov = (buffer_type, buffer_type)
        self.wrap_iov.append(self.last_iov)
        return header + body + trailer + (b"\x00" * 16)

    def unwrap(
        self,
        header: bytes,
        body: bytes,
        trailer: bytes,
        signature: bytes,
        sign_header: bool,
    ) -> bytes:
        buffer_type = spnego.iov.BufferType.sign_only if sign_header else spnego.iov.BufferType.data_readonly
        self.last_iov = (buffer_type, buffer_type)
        self.unwrap_iov.append(self.last_iov)
        return body


class StuckAuth(RecordingAuth):
    """Authentication that never completes and stops producing tokens."""

    def __init__(self) -> None:
        super().__init__(complete_after_step=999)
        self.complete = False

    def step(
        self,
        in_token: t.Optional[bytes] = None,
    ) -> pdu.SecTrailer:
        self.step_count += 1
        return pdu.SecTrailer(
            type=pdu.SecurityProvider.RPC_C_AUTHN_GSS_NEGOTIATE,
            level=pdu.AuthenticationLevel.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            pad_length=0,
            context_id=0,
            auth_value=b"",
        )


class FakeSyncTransport:
    def __init__(self, responses: t.List[bytes]) -> None:
        self.sent: t.List[bytes] = []
        self._responses = list(responses)
        self._pending = b""
        self.closed = False

    def _read(self, length: int) -> bytes:
        if not self._pending:
            if not self._responses:
                return b""
            self._pending = self._responses.pop(0)

        data = self._pending[:length]
        self._pending = self._pending[length:]
        return data

    def sendall(self, data: t.Union[bytes, bytearray]) -> None:
        self.sent.append(bytes(data))

    def recv(self, length: int) -> bytes:
        return self._read(length)

    def recv_into(self, buffer: t.Any) -> int:
        data = self._read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def shutdown(self, how: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class FakeAsyncReader:
    def __init__(self, responses: t.List[bytes]) -> None:
        self._pending = b""
        self._responses = list(responses)

    async def readexactly(self, length: int) -> bytes:
        if not self._pending:
            self._pending = self._responses.pop(0)

        data = self._pending[:length]
        self._pending = self._pending[length:]
        return data


class FakeAsyncWriter:
    def __init__(self) -> None:
        self.sent: t.List[bytes] = []
        self.closed = False

    def write(self, data: t.Union[bytes, bytearray]) -> None:
        self.sent.append(bytes(data))

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


def _sent_request_trailer(transport: FakeSyncTransport) -> verification.VerificationTrailer:
    sent = transport.sent[-1]
    msg = pdu.PDU.unpack(sent)
    assert isinstance(msg, request.Request)

    marker = verification.VerificationTrailer([]).signature
    trailer = msg.stub_data[msg.stub_data.index(marker) :]
    return verification.VerificationTrailer.unpack(trailer)


def test_compatible_mode_uses_negotiated_header_signing() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(True), _response()])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.ESTABLISHED
    assert rpc.header_signing is True
    assert rpc.header_signing_required is False

    rpc.request(0, 0, b"", verification_trailer=_client_verification_trailer())

    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.sign_only,
        spnego.iov.BufferType.sign_only,
    )

    trailer = _sent_request_trailer(transport)
    assert isinstance(trailer.commands[0], verification.CommandBitmask)
    assert trailer.commands[0].bits & verification.CommandBitmask.CLIENT_SUPPORT_HEADER_SIGNING
    assert isinstance(trailer.commands[-1], verification.CommandPContext)
    assert trailer.commands[-1].flags & verification.CommandFlags.SEC_VT_COMMAND_END


def test_compatible_mode_reports_body_only_protection() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(False), _response()])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())

    assert rpc.header_signing is False
    assert rpc.bind_state == client.BindState.ESTABLISHED

    rpc.request(0, 0, b"", verification_trailer=_client_verification_trailer())

    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.data_readonly,
        spnego.iov.BufferType.data_readonly,
    )

    trailer = _sent_request_trailer(transport)
    assert not any(isinstance(c, verification.CommandBitmask) for c in trailer.commands)


def test_required_header_signing_rejects_downgrade() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(False)])
    rpc = client.SyncRpcClient(transport, auth, require_header_signing=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Header signing was required but the peer did not negotiate support"):
        rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.FAILED
    with pytest.raises(ValueError, match="Cannot send a request"):
        rpc.request(0, 0, b"")

    assert len(transport.sent) == 1


def test_required_header_signing_without_auth_provider_fails_before_send() -> None:
    transport = FakeSyncTransport([_bind_ack(False)])
    rpc = client.SyncRpcClient(transport, require_header_signing=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Header signing requires an authentication provider"):
        rpc.bind(_contexts())

    assert len(transport.sent) == 0


def test_required_header_signing_without_provider_iov_support_fails_before_send() -> None:
    auth = RecordingAuth(supports_header_signing=False)
    transport = FakeSyncTransport([_bind_ack(True)])
    rpc = client.SyncRpcClient(transport, auth, require_header_signing=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="authentication provider does not support header signing"):
        rpc.bind(_contexts())

    assert len(transport.sent) == 0


def test_compatible_without_provider_iov_support_reports_body_only() -> None:
    auth = RecordingAuth(supports_header_signing=False)
    transport = FakeSyncTransport([_bind_ack(True), _response()])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())

    sent_bind = pdu.PDU.unpack(transport.sent[0])
    assert not sent_bind.header.packet_flags & pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN
    assert rpc.header_signing is False

    rpc.request(0, 0, b"", verification_trailer=_client_verification_trailer())
    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.data_readonly,
        spnego.iov.BufferType.data_readonly,
    )


@pytest.mark.parametrize("bind_support, alter_support", [(True, False), (False, True)])
def test_alter_context_contradiction_rejected(
    bind_support: bool,
    alter_support: bool,
) -> None:
    auth = RecordingAuth(complete_after_step=3)
    transport = FakeSyncTransport([_bind_ack(bind_support), _alter_context_response(alter_support)])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="inconsistent between Bind and AlterContext"):
        rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.FAILED
    with pytest.raises(ValueError, match="Cannot send a request"):
        rpc.request(0, 0, b"")


def test_incomplete_authentication_blocks_requests() -> None:
    auth = StuckAuth()
    transport = FakeSyncTransport([_bind_ack(True)])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Authentication did not complete"):
        rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.FAILED
    with pytest.raises(ValueError, match="Cannot send a request"):
        rpc.request(0, 0, b"")

    assert len(transport.sent) == 1


def test_rebind_cannot_weaken_header_signing() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(True), _bind_ack(False)])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())
    assert rpc.header_signing is True

    with pytest.raises(ValueError, match="Rebinding changed the negotiated header signing capability"):
        rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.FAILED


def test_rebind_to_same_capability_is_allowed() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(True), _bind_ack(True)])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())
    rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.ESTABLISHED
    assert rpc.header_signing is True


def test_verification_trailer_contradicts_negotiation() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(True)])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]
    rpc.bind(_contexts())

    trailer = verification.VerificationTrailer(
        [
            verification.CommandBitmask(
                flags=verification.CommandFlags.NONE,
                bits=0,
            ),
            verification.CommandPContext(
                flags=verification.CommandFlags.SEC_VT_COMMAND_END,
                interface_id=_ABSTRACT_SYNTAX,
                transfer_syntax=_TRANSFER_SYNTAX,
            ),
        ]
    )

    with pytest.raises(ValueError, match="does not claim negotiated header signing support"):
        rpc.request(0, 0, b"", verification_trailer=trailer)

    assert len(transport.sent) == 1


def test_verification_trailer_claims_unnegotiated_support() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(False)])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]
    rpc.bind(_contexts())

    trailer = verification.VerificationTrailer(
        [
            verification.CommandBitmask(
                flags=verification.CommandFlags.SEC_VT_COMMAND_END,
                bits=verification.CommandBitmask.CLIENT_SUPPORT_HEADER_SIGNING,
            )
        ]
    )

    with pytest.raises(ValueError, match="not negotiated"):
        rpc.request(0, 0, b"", verification_trailer=trailer)

    assert len(transport.sent) == 1


async def test_async_compatible_mode_uses_negotiated_header_signing() -> None:
    auth = RecordingAuth()
    reader = FakeAsyncReader([_bind_ack(True), _response()])
    writer = FakeAsyncWriter()
    rpc = client.AsyncRpcClient(reader, writer, auth)  # type: ignore[arg-type]

    await rpc.bind(_contexts())
    assert rpc.bind_state == client.BindState.ESTABLISHED
    assert rpc.header_signing is True

    await rpc.request(0, 0, b"", verification_trailer=_client_verification_trailer())
    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.sign_only,
        spnego.iov.BufferType.sign_only,
    )

    sent = pdu.PDU.unpack(writer.sent[-1])
    assert isinstance(sent, request.Request)
    marker = verification.VerificationTrailer([]).signature
    trailer = verification.VerificationTrailer.unpack(sent.stub_data[sent.stub_data.index(marker) :])
    assert isinstance(trailer.commands[0], verification.CommandBitmask)
    assert trailer.commands[0].bits & verification.CommandBitmask.CLIENT_SUPPORT_HEADER_SIGNING


async def test_async_required_header_signing_succeeds_when_supported() -> None:
    auth = RecordingAuth()
    reader = FakeAsyncReader([_bind_ack(True), _response()])
    writer = FakeAsyncWriter()
    rpc = client.AsyncRpcClient(reader, writer, auth, require_header_signing=True)  # type: ignore[arg-type]

    await rpc.bind(_contexts())
    assert rpc.bind_state == client.BindState.ESTABLISHED
    assert rpc.header_signing is True

    await rpc.request(0, 0, b"")
    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.sign_only,
        spnego.iov.BufferType.sign_only,
    )


async def test_async_required_header_signing_rejects_downgrade() -> None:
    auth = RecordingAuth()
    reader = FakeAsyncReader([_bind_ack(False)])
    writer = FakeAsyncWriter()
    rpc = client.AsyncRpcClient(reader, writer, auth, require_header_signing=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Header signing was required"):
        await rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.FAILED
    with pytest.raises(ValueError, match="Cannot send a request"):
        await rpc.request(0, 0, b"")

    assert len(writer.sent) == 1


async def test_async_compatible_mode_reports_body_only_protection() -> None:
    auth = RecordingAuth()
    reader = FakeAsyncReader([_bind_ack(False), _response()])
    writer = FakeAsyncWriter()
    rpc = client.AsyncRpcClient(reader, writer, auth)  # type: ignore[arg-type]

    await rpc.bind(_contexts())
    assert rpc.header_signing is False

    await rpc.request(0, 0, b"", verification_trailer=_client_verification_trailer())
    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.data_readonly,
        spnego.iov.BufferType.data_readonly,
    )


async def test_async_alter_context_contradiction_rejected() -> None:
    auth = RecordingAuth(complete_after_step=3)
    reader = FakeAsyncReader([_bind_ack(True), _alter_context_response(False)])
    writer = FakeAsyncWriter()
    rpc = client.AsyncRpcClient(reader, writer, auth)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="inconsistent between Bind and AlterContext"):
        await rpc.bind(_contexts())

    assert rpc.bind_state == client.BindState.FAILED


class MismatchedAuth(RecordingAuth):
    """Authentication double that records a weaker IOV type than requested."""

    def wrap(
        self,
        header: bytes,
        body: bytes,
        trailer: bytes,
        sign_header: bool,
    ) -> bytes:
        self.last_iov = (
            spnego.iov.BufferType.data_readonly,
            spnego.iov.BufferType.data_readonly,
        )
        return header + body + trailer + (b"\x00" * 16)


def test_provider_downgrade_is_detected() -> None:
    auth = MismatchedAuth()
    transport = FakeSyncTransport([_bind_ack(True), _response()])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())
    assert rpc.header_signing is True

    with pytest.raises(ValueError, match="did not apply the negotiated header protection"):
        rpc.request(0, 0, b"", verification_trailer=_client_verification_trailer())

    assert len(transport.sent) == 1  # the request was never sent with weaker protection


def test_bind_advertises_header_signing_when_authenticated() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(False), _response()])
    rpc = client.SyncRpcClient(transport, auth)  # type: ignore[arg-type]

    rpc.bind(_contexts())

    sent_bind = pdu.PDU.unpack(transport.sent[0])
    assert isinstance(sent_bind, bind.Bind)
    assert sent_bind.header.packet_flags & pdu.PacketFlags.PFC_SUPPORT_HEADER_SIGN
    assert rpc.header_signing is False


def test_required_header_signing_succeeds_when_supported() -> None:
    auth = RecordingAuth()
    transport = FakeSyncTransport([_bind_ack(True), _response()])
    rpc = client.SyncRpcClient(transport, auth, require_header_signing=True)  # type: ignore[arg-type]

    rpc.bind(_contexts())
    assert rpc.bind_state == client.BindState.ESTABLISHED
    assert rpc.header_signing is True

    rpc.request(0, 0, b"")
    assert auth.wrap_iov[-1] == (
        spnego.iov.BufferType.sign_only,
        spnego.iov.BufferType.sign_only,
    )


def test_unauthenticated_bind_reports_no_header_signing() -> None:
    transport = FakeSyncTransport([_bind_ack(False)])
    rpc = client.SyncRpcClient(transport)  # type: ignore[arg-type]

    rpc.bind(_contexts())

    assert rpc.header_signing is False
    assert rpc.bind_state == client.BindState.ESTABLISHED


def test_request_before_bind_is_rejected() -> None:
    transport = FakeSyncTransport([])
    rpc = client.SyncRpcClient(transport, RecordingAuth())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Cannot send a request while the RPC connection is in the UNBOUND state"):
        rpc.request(0, 0, b"")

    assert len(transport.sent) == 0
