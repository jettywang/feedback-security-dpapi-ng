# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import concurrent.futures
import enum
import socket
import typing as t
import uuid

import spnego.iov

from ._auth import AuthenticationProvider
from ._bind import (
    AlterContext,
    AlterContextResponse,
    Bind,
    BindAck,
    BindNak,
    ContextElement,
    ContextResultCode,
    SyntaxId,
)
from ._pdu import PDU, DataRep, Fault, PacketFlags, PacketType, PDUHeader, SecTrailer
from ._request import Request, Response
from ._verification import CommandBitmask, CommandFlags, VerificationTrailer

NDR = SyntaxId(uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = SyntaxId(uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)

T = t.TypeVar("T")


class BindState(enum.Enum):
    """The authentication/binding state of an RPC connection."""

    UNBOUND = enum.auto()
    BINDING = enum.auto()
    ESTABLISHED = enum.auto()
    FAILED = enum.auto()


async def async_create_rpc_connection(
    server: str,
    port: int = 135,
    connection_timeout: int = 5,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: t.Optional[str] = None,
    require_header_signing: bool = False,
) -> AsyncRpcClient:
    auth_provider = None
    if auth_protocol:
        auth_provider = AuthenticationProvider(username, password, server, auth_protocol)

    conn_future = asyncio.open_connection(server, port=port)
    reader, writer = await asyncio.wait_for(conn_future, connection_timeout)

    return AsyncRpcClient(reader, writer, auth_provider, require_header_signing=require_header_signing)


def create_rpc_connection(
    server: str,
    port: int = 135,
    connection_timeout: int = 5,
    username: t.Optional[str] = None,
    password: t.Optional[str] = None,
    auth_protocol: t.Optional[str] = None,
    require_header_signing: bool = False,
) -> SyncRpcClient:
    auth_provider = None
    if auth_protocol:
        auth_provider = AuthenticationProvider(username, password, server, auth_protocol)

    sock = socket.create_connection(
        (server, port),
        timeout=connection_timeout,
    )
    sock.settimeout(None)

    return SyncRpcClient(sock, auth_provider, require_header_signing=require_header_signing)


class RpcClient:
    def __init__(
        self,
        auth: t.Optional[AuthenticationProvider] = None,
        *,
        require_header_signing: bool = False,
    ) -> None:
        self._auth = auth
        self._require_header_signing = require_header_signing
        self._sign_header = False
        self._state = BindState.UNBOUND
        self._previous_header_signing: t.Optional[bool] = None

    @property
    def header_signing(self) -> bool:
        """Whether the RPC PDU header and security trailer are integrity protected.

        This is the protection that was actually negotiated with the peer, not
        just the capability that was advertised by this client. When this is
        ``False`` only the PDU body is protected by the authentication
        provider; when it is ``True`` the PDU header and security trailer are
        also covered by the signature.
        """
        return self._sign_header

    @property
    def header_signing_required(self) -> bool:
        """Whether this client refuses to continue without header signing."""
        return self._require_header_signing

    @property
    def bind_state(self) -> BindState:
        """The current authentication/binding state of the connection."""
        return self._state

    def _begin_bind(self) -> None:
        if self._state == BindState.FAILED:
            raise ValueError("Cannot bind on a connection that previously failed to bind")

        if self._require_header_signing:
            if not self._auth:
                self._state = BindState.FAILED
                raise ValueError("Header signing requires an authentication provider")
            if not self._auth.supports_header_signing:
                self._state = BindState.FAILED
                raise ValueError("The authentication provider does not support header signing")

        # Track the capability of the previous successful binding so that a
        # rebind cannot silently weaken the established protection.
        self._previous_header_signing = self._sign_header if self._state == BindState.ESTABLISHED else None
        self._sign_header = False
        self._state = BindState.BINDING

    def _record_negotiation(
        self,
        ack: t.Union[BindAck, AlterContextResponse],
        *,
        initial: bool,
    ) -> bool:
        supported = (
            bool(ack.header.packet_flags & PacketFlags.PFC_SUPPORT_HEADER_SIGN)
            and self._auth is not None
            and self._auth.supports_header_signing
        )

        if initial:
            negotiated = supported
        elif supported != self._sign_header:
            # Bind and AlterContext must agree on whether header signing is in
            # use. A changing result is a downgrade/ambiguity, not something
            # that should silently alter the protection of business requests.
            self._state = BindState.FAILED
            raise ValueError("Header signing negotiation is inconsistent between Bind and AlterContext responses")
        else:
            negotiated = self._sign_header

        if self._require_header_signing and not negotiated:
            self._state = BindState.FAILED
            raise ValueError("Header signing was required but the peer did not negotiate support")

        self._sign_header = negotiated
        return negotiated

    def _finish_bind(self) -> None:
        if self._auth and not self._auth.complete:
            self._state = BindState.FAILED
            raise ValueError("Authentication did not complete")

        if self._require_header_signing and not self._sign_header:
            self._state = BindState.FAILED
            raise ValueError("Header signing was required but was not negotiated")

        if self._previous_header_signing is not None and self._previous_header_signing != self._sign_header:
            self._state = BindState.FAILED
            raise ValueError("Rebinding changed the negotiated header signing capability of the connection")

        self._state = BindState.ESTABLISHED

    def _assert_can_request(self) -> None:
        if self._state != BindState.ESTABLISHED:
            raise ValueError(f"Cannot send a request while the RPC connection is in the {self._state.name} state")

        if self._auth and not self._auth.complete:
            raise ValueError("Cannot send a request before authentication has completed")

    def _normalize_verification_trailer(
        self,
        verification_trailer: VerificationTrailer,
    ) -> VerificationTrailer:
        bitmasks = [c for c in verification_trailer.commands if isinstance(c, CommandBitmask)]
        if len(bitmasks) > 1:
            raise ValueError("Verification trailer contains multiple header signing bitmask commands")

        if bitmasks:
            supported = bool(bitmasks[0].bits & CommandBitmask.CLIENT_SUPPORT_HEADER_SIGNING)
            if supported and not self._sign_header:
                raise ValueError("Verification trailer claims header signing support but it was not negotiated")
            if not supported and self._sign_header:
                raise ValueError("Verification trailer does not claim negotiated header signing support")

            return verification_trailer

        if not self._sign_header:
            return verification_trailer

        # When header signing was negotiated, record it in the verification
        # trailer as the first command (matching the Windows client layout).
        # The existing SEC_VT_COMMAND_END remains on the final command.
        commands = list(verification_trailer.commands)
        if not commands:
            return VerificationTrailer(
                commands=[
                    CommandBitmask(
                        flags=CommandFlags.SEC_VT_COMMAND_END,
                        bits=CommandBitmask.CLIENT_SUPPORT_HEADER_SIGNING,
                    )
                ]
            )

        return VerificationTrailer(
            commands=[
                CommandBitmask(
                    flags=CommandFlags.NONE,
                    bits=CommandBitmask.CLIENT_SUPPORT_HEADER_SIGNING,
                ),
                *commands,
            ]
        )

    def _verify_header_iov(self) -> None:
        # The IOV buffer types are the proof of what was actually protected.
        # A provider that recorded a different type than requested means the
        # negotiated protection was not applied to the header/trailer.
        actual = getattr(self._auth, "last_iov", None)
        if actual is None:
            return

        expected = spnego.iov.BufferType.sign_only if self._sign_header else spnego.iov.BufferType.data_readonly
        if actual != (expected, expected):
            raise ValueError("Authentication provider did not apply the negotiated header protection")

    def _create_pdu_header(
        self,
        packet_type: PacketType,
        auth_len: int,
        call_id: int,
        *,
        flags: PacketFlags = PacketFlags.NONE,
    ) -> PDUHeader:
        return PDUHeader(
            version=5,
            version_minor=0,
            packet_type=packet_type,
            packet_flags=flags | PacketFlags.PFC_FIRST_FRAG | PacketFlags.PFC_LAST_FRAG,
            data_rep=DataRep(),
            frag_len=0,  # Set after building the PDU
            auth_len=auth_len,
            call_id=call_id,
        )

    def _create_bind(
        self,
        contexts: t.List[ContextElement],
        sec_trailer: t.Optional[SecTrailer] = None,
    ) -> Bind:
        flags = PacketFlags.NONE

        auth_len = 0
        if sec_trailer:
            # Only advertise a capability this client can actually apply. What
            # was actually negotiated is tracked from the bind responses.
            if self._auth is not None and self._auth.supports_header_signing:
                flags |= PacketFlags.PFC_SUPPORT_HEADER_SIGN
            auth_len = len(sec_trailer.auth_value)

        return Bind(
            header=self._create_pdu_header(
                PacketType.BIND,
                auth_len,
                1,
                flags=flags,
            ),
            sec_trailer=sec_trailer,
            max_xmit_frag=5840,
            max_recv_frag=5840,
            assoc_group=0,
            contexts=contexts,
        )

    def _create_alter_context(
        self,
        contexts: t.List[ContextElement],
        sec_trailer: SecTrailer,
    ) -> AlterContext:
        flags = PacketFlags.PFC_SUPPORT_HEADER_SIGN if self._sign_header else PacketFlags.NONE

        return AlterContext(
            header=self._create_pdu_header(
                PacketType.ALTER_CONTEXT,
                len(sec_trailer.auth_value),
                1,
                flags=flags,
            ),
            sec_trailer=sec_trailer,
            max_xmit_frag=5840,
            max_recv_frag=5840,
            assoc_group=0,
            contexts=contexts,
        )

    def _create_request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
        *,
        verification_trailer: t.Optional[VerificationTrailer] = None,
    ) -> tuple[Request, t.Optional[tuple[int, int]]]:
        if verification_trailer:
            verification_trailer = self._normalize_verification_trailer(verification_trailer)

            # The verification trailer needs to be aligned to the next 4 byte
            # boundary.
            padding = -len(stub_data) % 4
            stub_data += (b"\x00" * padding) + verification_trailer.pack()

        auth_len = 0
        sec_trailer = None
        encrypt_offsets = None
        if self._auth:
            # If the security trailer is present it must be aligned to the
            # next 16 byte boundary after the stub data. This padding is
            # included as part of the stub data to be encrypted.
            pad_length = -len(stub_data) % 16
            stub_data += b"\x00" * pad_length
            sec_trailer = self._auth.get_empty_trailer(pad_length)
            auth_len = len(sec_trailer.auth_value)
            encrypt_offsets = (24, 24 + len(stub_data))

        return (
            Request(
                header=self._create_pdu_header(
                    PacketType.REQUEST,
                    auth_len,
                    1,
                ),
                sec_trailer=sec_trailer,
                alloc_hint=len(stub_data),
                context_id=context_id,
                opnum=opnum,
                obj=None,
                stub_data=stub_data,
            ),
            encrypt_offsets,
        )

    def _prepare_pdu(
        self,
        pdu: PDU,
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> t.Union[bytes, bytearray]:
        b_pdu: t.Union[bytes, bytearray] = bytearray(pdu.pack())
        view = memoryview(b_pdu)
        view[8:10] = len(b_pdu).to_bytes(2, byteorder="little")

        if self._auth and encrypt_offsets:
            view = memoryview(b_pdu)
            header = view[: encrypt_offsets[0]].tobytes()
            body = view[encrypt_offsets[0] : encrypt_offsets[1]].tobytes()
            sec_trailer = view[encrypt_offsets[1] : encrypt_offsets[1] + 8].tobytes()
            b_pdu = self._auth.wrap(header, body, sec_trailer, self._sign_header)
            self._verify_header_iov()

        return b_pdu

    def _process_bind_ack(
        self,
        ack: t.Union[BindAck, AlterContextResponse],
        contexts: t.List[ContextElement],
        *,
        initial: bool,
    ) -> tuple[t.List[ContextElement], t.Optional[bytes]]:
        if len(ack.results) < len(contexts):
            raise ValueError("Bind response did not include a result for each requested context")

        alter_contexts = []
        for idx, c in enumerate(contexts):
            context_res = ack.results[idx]
            if context_res.result == ContextResultCode.ACCEPTANCE:
                alter_contexts.append(c)

        self._record_negotiation(ack, initial=initial)

        auth_value = None
        if ack.sec_trailer:
            auth_value = ack.sec_trailer.auth_value

        return alter_contexts, auth_value

    def _process_response(
        self,
        response: bytearray,
        pdu_header: PDUHeader,
        resp_type: t.Type[T],
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> T:
        if self._auth and encrypt_offsets and pdu_header.auth_len:
            view = memoryview(response)

            sec_trailer_offset = pdu_header.frag_len - (pdu_header.auth_len + 8)
            header = view[: encrypt_offsets[0]].tobytes()
            body = view[encrypt_offsets[0] : sec_trailer_offset].tobytes()
            sec_trailer = view[sec_trailer_offset : sec_trailer_offset + 8].tobytes()
            signature = view[sec_trailer_offset + 8 :].tobytes()
            dec_stub = self._auth.unwrap(header, body, sec_trailer, signature, self._sign_header)
            response[encrypt_offsets[0] : sec_trailer_offset] = dec_stub

        pdu_resp = PDU.unpack(response)
        if isinstance(pdu_resp, BindNak):
            raise ValueError(f"Received BindNack with reason 0x{pdu_resp.reject_reason:08X}")
        elif isinstance(pdu_resp, Fault):
            raise ValueError(f"Receive Fault with status 0x{pdu_resp.status:08X}")
        elif not isinstance(pdu_resp, resp_type):
            raise ValueError(
                f"Received unexpected PDU response of {type(pdu_resp).__name__} when expecting {resp_type.__name__}"
            )

        return pdu_resp


class AsyncRpcClient(RpcClient):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        auth: t.Optional[AuthenticationProvider] = None,
        *,
        require_header_signing: bool = False,
    ) -> None:
        super().__init__(auth, require_header_signing=require_header_signing)
        self._reader = reader
        self._writer = writer

    async def __aenter__(self) -> AsyncRpcClient:
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()

    async def bind(
        self,
        contexts: t.List[ContextElement],
    ) -> BindAck:
        self._begin_bind()

        sec_trailer = None
        if self._auth:
            sec_trailer = await self._wrap_sync(self._auth.step)

        bind = self._create_bind(contexts, sec_trailer)
        try:
            bind_ack = await self._send_pdu(bind, BindAck)

            if not self._auth:
                self._finish_bind()
                return bind_ack

            final_contexts, in_token = self._process_bind_ack(bind_ack, contexts, initial=True)

            while not self._auth.complete:
                sec_trailer = await self._wrap_sync(self._auth.step, (in_token or b""))
                if not sec_trailer.auth_value:
                    break

                alter_context = self._create_alter_context(final_contexts, sec_trailer)
                alter_resp = await self._send_pdu(alter_context, AlterContextResponse)
                _, in_token = self._process_bind_ack(alter_resp, final_contexts, initial=False)

            self._finish_bind()
            return bind_ack
        except Exception:
            self._state = BindState.FAILED
            raise

    async def request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
        *,
        verification_trailer: t.Optional[VerificationTrailer] = None,
    ) -> Response:
        self._assert_can_request()

        req, encrypt_offsets = self._create_request(
            context_id,
            opnum,
            stub_data,
            verification_trailer=verification_trailer,
        )
        return await self._send_pdu(req, Response, encrypt_offsets=encrypt_offsets)

    async def _send_pdu(
        self,
        pdu: PDU,
        resp_type: t.Type[T],
        *,
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> T:
        b_pdu = self._prepare_pdu(pdu, encrypt_offsets)

        self._writer.write(b_pdu)
        await self._writer.drain()

        header = await self._reader.readexactly(16)
        resp_header = PDUHeader.unpack(header)

        resp = bytearray(resp_header.frag_len)
        view = memoryview(resp)
        view[:16] = header
        view[16:] = await self._reader.readexactly(len(resp) - 16)

        return self._process_response(resp, resp_header, resp_type, encrypt_offsets)

    async def _wrap_sync(
        self,
        func: t.Callable[..., T],
        *args: t.Any,
    ) -> T:
        exec = concurrent.futures.ThreadPoolExecutor()
        return await asyncio.get_event_loop().run_in_executor(exec, func, *args)


class SyncRpcClient(RpcClient):
    def __init__(
        self,
        sock: socket.socket,
        auth: t.Optional[AuthenticationProvider] = None,
        *,
        require_header_signing: bool = False,
    ) -> None:
        super().__init__(auth, require_header_signing=require_header_signing)
        self._sock = sock

    def __enter__(self) -> SyncRpcClient:
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        self._sock.close()

    def bind(
        self,
        contexts: t.List[ContextElement],
    ) -> BindAck:
        self._begin_bind()

        sec_trailer = None
        if self._auth:
            sec_trailer = self._auth.step()

        bind = self._create_bind(contexts, sec_trailer)
        try:
            bind_ack = self._send_pdu(bind, BindAck)

            if not self._auth:
                self._finish_bind()
                return bind_ack

            final_contexts, in_token = self._process_bind_ack(bind_ack, contexts, initial=True)

            while not self._auth.complete:
                sec_trailer = self._auth.step(in_token or b"")
                if not sec_trailer.auth_value:
                    break

                alter_context = self._create_alter_context(final_contexts, sec_trailer)
                alter_resp = self._send_pdu(alter_context, AlterContextResponse)
                _, in_token = self._process_bind_ack(alter_resp, final_contexts, initial=False)

            self._finish_bind()
            return bind_ack
        except Exception:
            self._state = BindState.FAILED
            raise

    def request(
        self,
        context_id: int,
        opnum: int,
        stub_data: bytes,
        *,
        verification_trailer: t.Optional[VerificationTrailer] = None,
    ) -> Response:
        self._assert_can_request()

        req, encrypt_offsets = self._create_request(
            context_id,
            opnum,
            stub_data,
            verification_trailer=verification_trailer,
        )
        return self._send_pdu(req, Response, encrypt_offsets=encrypt_offsets)

    def _send_pdu(
        self,
        pdu: PDU,
        resp_type: t.Type[T],
        *,
        encrypt_offsets: t.Optional[tuple[int, int]] = None,
    ) -> T:
        b_pdu = self._prepare_pdu(pdu, encrypt_offsets)
        self._sock.sendall(b_pdu)

        header = self._sock.recv(16)
        resp_header = PDUHeader.unpack(header)

        resp = bytearray(resp_header.frag_len)
        view = memoryview(resp)
        view[:16] = header
        view = view[16:]

        while view:
            read = self._sock.recv_into(view)
            view = view[read:]

        return self._process_response(resp, resp_header, resp_type, encrypt_offsets)
