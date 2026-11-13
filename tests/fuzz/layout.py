"""Independent layout inspector for GroupKeyEnvelope and KeyIdentifier.

This module deliberately does not call ``unpack``. It slices the wire format
by hand using the field order implemented by ``dpapi_ng._gkdi`` and
``dpapi_ng._blob``. The tests use it as a second opinion about where each
declared field physically starts and ends, so a parser that consumes bytes
from a neighbouring field cannot pass merely by re-packing to the same bytes.
"""

from __future__ import annotations

import dataclasses
import typing as t

MAGIC = b"KDSK"
ENVELOPE_HEADER_SIZE = 80
KEY_IDENTIFIER_HEADER_SIZE = 52

# (field name, offset of its little-endian uint32 length, kind), in physical
# wire order after the fixed header.
ENVELOPE_FIELDS: t.Tuple[t.Tuple[str, int, str], ...] = (
    ("kdf_algorithm", 40, "utf16"),
    ("kdf_parameters", 44, "bytes"),
    ("secret_algorithm", 48, "utf16"),
    ("secret_parameters", 52, "bytes"),
    ("domain_name", 72, "utf16"),
    ("forest_name", 76, "utf16"),
    ("l1_key", 64, "bytes"),
    ("l2_key", 68, "bytes"),
)

KEY_IDENTIFIER_FIELDS: t.Tuple[t.Tuple[str, int, str], ...] = (
    ("key_info", 40, "bytes"),
    ("domain_name", 44, "utf16"),
    ("forest_name", 48, "utf16"),
)

DEVIATIONS = (
    "short_header",
    "bad_magic",
    "length_overrun",
    "short_string",
    "odd_utf16",
    "early_terminator",
    "bad_terminator",
    "trailing_bytes",
)


@dataclasses.dataclass(frozen=True)
class Span:
    """One field as sliced from the physical buffer."""

    name: str
    start: int
    end: int
    kind: str
    declared: int
    terminator_start: t.Optional[int] = None
    value: t.Union[str, bytes, None] = None

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


@dataclasses.dataclass(frozen=True)
class Header:
    """Fixed header values, sliced at their documented offsets."""

    version: int
    magic: bytes
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: bytes


@dataclasses.dataclass(frozen=True)
class Layout:
    """Result of the independent inspection.

    ``deviation`` is ``None`` for a well-formed buffer. Otherwise it names the
    first structural fault, ``field`` names the responsible field, and
    ``checkpoint`` is the offset where a minimal reproducer should look.
    """

    deviation: t.Optional[str]
    field: t.Optional[str]
    detail: str
    spans: t.Tuple[Span, ...]
    consumed_end: int
    buffer_length: int
    header: t.Optional[Header] = None

    @property
    def is_valid(self) -> bool:
        return self.deviation is None

    @property
    def checkpoint(self) -> int:
        return self.consumed_end

    def field_span(self, name: str) -> t.Optional[Span]:
        for span in self.spans:
            if span.name == name:
                return span
        return None

    def overlaps(self) -> t.Tuple[t.Tuple[str, str], ...]:
        pairs = []
        for index, left in enumerate(self.spans):
            for right in self.spans[index + 1 :]:
                if left.name != right.name and left.overlaps(right):
                    pairs.append((left.name, right.name))
        return tuple(pairs)

    def explain(self) -> str:
        if self.deviation is None:
            return "layout ok ({} bytes consumed, {} in buffer)".format(self.consumed_end, self.buffer_length)
        return "layout {!r} in {!r}: {}; checkpoint offset {}".format(
            self.deviation, self.field, self.detail, self.checkpoint
        )


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _embedded_nul(body: bytes) -> t.Optional[int]:
    for offset in range(0, len(body) - 1, 2):
        if body[offset : offset + 2] == b"\x00\x00":
            return offset
    return None


def _inspect(
    data: t.Union[bytes, bytearray, memoryview],
    header_size: int,
    fields: t.Tuple[t.Tuple[str, int, str], ...],
) -> Layout:
    raw = bytes(data)
    length = len(raw)

    if length < 8:
        return Layout("short_header", None, "buffer {} < 8 bytes for version/magic".format(length), (), length, length)
    if raw[4:8] != MAGIC:
        return Layout("bad_magic", "magic", "magic {} is not KDSK".format(raw[4:8].hex()), (), 8, length)
    if length < header_size:
        return Layout(
            "short_header",
            "header",
            "buffer {} < {} byte fixed header".format(length, header_size),
            (),
            length,
            length,
        )

    spans: t.List[Span] = []
    cursor = header_size

    for name, length_offset, kind in fields:
        declared = _u32(raw, length_offset)
        start = cursor

        if kind == "utf16" and declared < 2:
            return Layout(
                "short_string",
                name,
                "declared {} < 2 byte NUL terminator".format(declared),
                tuple(spans),
                start,
                length,
            )
        if kind == "utf16" and declared % 2:
            return Layout(
                "odd_utf16",
                name,
                "declared {} is not a whole UTF-16 code unit".format(declared),
                tuple(spans),
                start,
                length,
            )

        end = start + declared
        if end > length:
            return Layout(
                "length_overrun",
                name,
                "declared {} bytes from {} ends at {}, buffer is {}".format(declared, start, end, length),
                tuple(spans),
                start,
                length,
            )

        if kind == "utf16":
            terminator_start = end - 2
            terminator = raw[terminator_start:end]
            if terminator != b"\x00\x00":
                return Layout(
                    "bad_terminator",
                    name,
                    "final code unit {} at {} is not NUL".format(terminator.hex(), terminator_start),
                    tuple(spans),
                    terminator_start,
                    length,
                )
            body = raw[start:terminator_start]
            embedded = _embedded_nul(body)
            if embedded is not None:
                return Layout(
                    "early_terminator",
                    name,
                    "NUL code unit at {} but {} bytes follow in the declared field".format(
                        start + embedded, len(body) - embedded
                    ),
                    tuple(spans),
                    start + embedded,
                    length,
                )
            try:
                value: t.Union[str, bytes] = body.decode("utf-16-le")
            except UnicodeDecodeError as exc:
                error_offset = start + getattr(exc, "start", 0)
                return Layout(
                    "odd_utf16",
                    name,
                    "body {}:{} is not UTF-16: {} (first bad unit at {})".format(
                        start, terminator_start, exc, error_offset
                    ),
                    tuple(spans),
                    error_offset,
                    length,
                )
            spans.append(
                Span(
                    name=name,
                    start=start,
                    end=end,
                    kind=kind,
                    declared=declared,
                    terminator_start=terminator_start,
                    value=value,
                )
            )
        else:
            spans.append(
                Span(
                    name=name,
                    start=start,
                    end=end,
                    kind=kind,
                    declared=declared,
                    value=raw[start:end],
                )
            )

        cursor = end

    if cursor < length:
        return Layout(
            "trailing_bytes",
            None,
            "{} bytes after the last field".format(length - cursor),
            tuple(spans),
            cursor,
            length,
        )

    header = Header(
        version=_u32(raw, 0),
        magic=raw[4:8],
        flags=_u32(raw, 8),
        l0=_u32(raw, 12),
        l1=_u32(raw, 16),
        l2=_u32(raw, 20),
        root_key_identifier=raw[24:40],
    )

    return Layout(None, None, "", tuple(spans), cursor, length, header)


def inspect_envelope(data: t.Union[bytes, bytearray, memoryview]) -> Layout:
    """Slice a Group Key Envelope independently of ``GroupKeyEnvelope.unpack``."""
    return _inspect(data, ENVELOPE_HEADER_SIZE, ENVELOPE_FIELDS)


def inspect_key_identifier(data: t.Union[bytes, bytearray, memoryview]) -> Layout:
    """Slice a Key Identifier independently of ``KeyIdentifier.unpack``."""
    return _inspect(data, KEY_IDENTIFIER_HEADER_SIZE, KEY_IDENTIFIER_FIELDS)
