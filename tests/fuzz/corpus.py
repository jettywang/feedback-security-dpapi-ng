"""Deterministic, bounded mutation corpus for the two GKDI structs.

Seeds come only from locally constructed ``pack()`` output. No real domain,
forest, key, or host data is involved: every name is RFC 2606 ``.invalid``
and every key byte is derived synthetically. The corpus is a pure function of
``(struct, seed, count)``; each :class:`Case` records the structured edit it
applies, the byte offsets of those edits, and a category so normal samples and
each mutation class stay separable.
"""

from __future__ import annotations

import dataclasses
import hashlib
import random
import typing as t
import uuid

from dpapi_ng import _blob as blob
from dpapi_ng import _gkdi as gkdi

from . import layout as layout_mod

MASTER_SEED = 0x5EC10F1
DEFAULT_SEED = 20261113
DEFAULT_CASES = 220
MAX_CASE_BYTES = 4096

ENVELOPE = "envelope"
KEY_IDENTIFIER = "key_identifier"
STRUCTS = (ENVELOPE, KEY_IDENTIFIER)

# Case categories, one per structural area the task asks to exercise.
NORMAL = "normal"
LENGTH_PREFIX = "length_prefix"
TERMINATOR = "terminator"
BOUNDARY = "boundary"
FLAGS = "flags"
TRUNCATION = "truncation"
TRAILING = "trailing"

CATEGORIES = (NORMAL, LENGTH_PREFIX, TERMINATOR, BOUNDARY, FLAGS, TRUNCATION, TRAILING)


@dataclasses.dataclass(frozen=True)
class Case:
    """One deterministic sample and the structured edits that made it."""

    struct: str
    name: str
    category: str
    data: bytes
    edits: t.Tuple[t.Tuple[str, int, int], ...] = ()
    targeted_field: t.Optional[str] = None
    description: str = ""

    def label(self) -> str:
        return "{}:{}".format(self.struct, self.name)

    def summary(self) -> str:
        return "{} ({} bytes; edits={}; field={})".format(
            self.label(), len(self.data), self.edits or "-", self.targeted_field or "-"
        )


HEADER_NAMES = {
    ENVELOPE: {
        0: "version",
        8: "flags",
        12: "l0",
        16: "l1",
        20: "l2",
        24: "root_key_identifier",
        40: "kdf_algorithm_len",
        44: "kdf_parameters_len",
        48: "secret_algorithm_len",
        52: "secret_parameters_len",
        56: "private_key_length",
        60: "public_key_length",
        64: "l1_key_len",
        68: "l2_key_len",
        72: "domain_name_len",
        76: "forest_name_len",
    },
    KEY_IDENTIFIER: {
        0: "version",
        8: "flags",
        12: "l0",
        16: "l1",
        20: "l2",
        24: "root_key_identifier",
        40: "key_info_len",
        44: "domain_name_len",
        48: "forest_name_len",
    },
}

ALL_LENGTH_FIELDS = {
    struct: tuple(name for name in names.values() if name.endswith("_len")) for struct, names in HEADER_NAMES.items()
}

BYTE_LENGTH_FIELDS = {
    ENVELOPE: ("kdf_parameters_len", "secret_parameters_len", "l1_key_len", "l2_key_len"),
    KEY_IDENTIFIER: ("key_info_len",),
}

STRING_LENGTH_FIELDS = {
    ENVELOPE: ("kdf_algorithm_len", "secret_algorithm_len", "domain_name_len", "forest_name_len"),
    KEY_IDENTIFIER: ("domain_name_len", "forest_name_len"),
}

SCALAR_FIELDS = {
    ENVELOPE: ("private_key_length", "public_key_length"),
    KEY_IDENTIFIER: (),
}

LENGTH_OFFSETS = {
    struct: {name: offset for offset, name in names.items() if name.endswith("_len")}
    for struct, names in HEADER_NAMES.items()
}


def _names(index: int) -> t.Tuple[str, str]:
    """Synthetic names of equal byte length, so swaps stay layout-neutral."""
    return (
        "alpha-{}.invalid".format(index),
        "bravo-{}.invalid".format(index),
    )


def _derived_bytes(label: str, count: int) -> bytes:
    out = bytearray()
    block = 0
    while len(out) < count:
        digest = hashlib.sha256("{}:{}:{}".format(MASTER_SEED, label, block).encode()).digest()
        out.extend(digest)
        block += 1
    return bytes(out[:count])


def envelope_struct(index: int = 0) -> gkdi.GroupKeyEnvelope:
    domain, forest = _names(index)
    return gkdi.GroupKeyEnvelope(
        version=1,
        flags=2,
        l0=1000 + index,
        l1=31 - (index % 8),
        l2=7 + (index % 4),
        root_key_identifier=uuid.UUID(bytes=_derived_bytes("rkid:{}".format(index), 16)),
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=b"\x00\x00\x00\x00\x01\x00\x00\x00" + b"\x0e\x00\x00\x00\x00\x00\x00\x00" + b"SHA512\x00\x00",
        secret_algorithm="DH",
        secret_parameters=_derived_bytes("dh:{}".format(index), 16),
        private_key_length=512,
        public_key_length=2048,
        domain_name=domain,
        forest_name=forest,
        l1_key=_derived_bytes("l1:{}".format(index), 32),
        l2_key=_derived_bytes("l2:{}".format(index), 32),
    )


def key_identifier_struct(index: int = 0) -> blob.KeyIdentifier:
    domain, forest = _names(index)
    return blob.KeyIdentifier(
        version=1,
        flags=1 if index % 2 else 0,
        l0=1000 + index,
        l1=31 - (index % 8),
        l2=7 + (index % 4),
        root_key_identifier=uuid.UUID(bytes=_derived_bytes("rkid:{}".format(index), 16)),
        key_info=_derived_bytes("key-info:{}".format(index), 64),
        domain_name=domain,
        forest_name=forest,
    )


def base_sample(struct: str, index: int = 0) -> t.Tuple[t.Union[gkdi.GroupKeyEnvelope, blob.KeyIdentifier], bytes]:
    value: t.Union[gkdi.GroupKeyEnvelope, blob.KeyIdentifier]
    if struct == ENVELOPE:
        value = envelope_struct(index)
    else:
        value = key_identifier_struct(index)
    return value, value.pack()


def inspector(struct: str, data: bytes) -> layout_mod.Layout:
    return layout_mod.inspect_envelope(data) if struct == ENVELOPE else layout_mod.inspect_key_identifier(data)


def field_span(struct: str, data: bytes, name: str) -> layout_mod.Span:
    found = inspector(struct, data).field_span(name)
    if found is None:
        raise KeyError("field {} is absent from {}".format(name, struct))
    return found


def _edit(name: str, offset: int, before: int, after: int) -> t.Tuple[str, int, int]:
    return (name, offset, after - before)


def _put_u32(data: bytes, offset: int, value: int) -> bytes:
    return data[:offset] + value.to_bytes(4, "little") + data[offset + 4 :]


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _replace(data: bytes, start: int, end: int, replacement: bytes) -> bytes:
    return data[:start] + replacement + data[end:]


def _length_case(struct: str, base: bytes, field: str, label: str, value: int, index: int, description: str) -> Case:
    offset = LENGTH_OFFSETS[struct][field]
    original = _u32(base, offset)
    return Case(
        struct=struct,
        name="len:{}.{}.{}".format(field, label, index),
        category=LENGTH_PREFIX,
        data=_put_u32(base, offset, value),
        edits=(_edit(field, offset, original, value),),
        targeted_field=field,
        description=description,
    )


def _rotating_fields(struct: str, index: int, seed: int) -> t.Tuple[str, str]:
    """Two consecutive uint32 header fields, rotating over every index."""
    rotation = list(ALL_LENGTH_FIELDS[struct]) + list(SCALAR_FIELDS[struct])
    start = (seed ^ MASTER_SEED) % len(rotation)
    first = rotation[(start + index - 1) % len(rotation)]
    second = rotation[(start + index) % len(rotation)]
    return first, second


def _length_cases(struct: str, base: bytes, index: int, seed: int) -> t.List[Case]:
    cases: t.List[Case] = []
    offsets_by_name = {name: offset for offset, name in HEADER_NAMES[struct].items()}

    for field in _rotating_fields(struct, index, seed):
        offset = offsets_by_name[field]
        original = _u32(base, offset)
        variants = (
            ("zero", 0),
            ("one", 1),
            ("minus-two", max(0, original - 2)),
            ("plus-two", original + 2),
            ("u32-max", 0xFFFFFFFF),
        )
        if field in SCALAR_FIELDS[struct]:
            cases.append(
                Case(
                    struct=struct,
                    name="scalar:{}.{}".format(field, index),
                    category=LENGTH_PREFIX,
                    data=_put_u32(base, offset, 0xFFFFFFFF),
                    edits=(_edit(field, offset, original, 0xFFFFFFFF),),
                    targeted_field=field,
                    description="uint32 metadata {} {} -> 0xFFFFFFFF (not a byte length)".format(field, original),
                )
            )
            continue
        if field not in LENGTH_OFFSETS[struct]:
            continue
        for label, value in variants:
            cases.append(
                _length_case(
                    struct,
                    base,
                    field,
                    label,
                    value,
                    index,
                    "{} length {} -> {}".format(field, original, value),
                )
            )

    # Correlate two byte-length fields in one sample: shrink the earlier
    # region and grow the later by exactly the same amount, keeping the total
    # constant while moving the boundary between them.
    binary = BYTE_LENGTH_FIELDS[struct]
    if len(binary) >= 2:
        first, second = binary[0], binary[-1]
        first_original = _u32(base, LENGTH_OFFSETS[struct][first])
        second_original = _u32(base, LENGTH_OFFSETS[struct][second])
        new_first = max(0, first_original // 2)
        new_second = second_original + (first_original - new_first)
        data = _put_u32(base, LENGTH_OFFSETS[struct][first], new_first)
        data = _put_u32(data, LENGTH_OFFSETS[struct][second], new_second)
        cases.append(
            Case(
                struct=struct,
                name="paired-length:{}.{}.{}".format(first, second, index),
                category=BOUNDARY,
                data=data,
                edits=(
                    _edit(first, LENGTH_OFFSETS[struct][first], first_original, new_first),
                    _edit(second, LENGTH_OFFSETS[struct][second], second_original, new_second),
                ),
                targeted_field=first,
                description="{} -{} bytes, {} +{} bytes, total fixed".format(
                    first, first_original - new_first, second, first_original - new_first
                ),
            )
        )

    return cases


def _compensated_string_pairs(struct: str, base: bytes, index: int) -> t.List[Case]:
    """Move a string boundary into a neighbour while holding the total fixed."""
    cases: t.List[Case] = []
    partner_of = {
        "domain_name_len": "forest_name_len",
        "forest_name_len": "domain_name_len",
        "kdf_algorithm_len": "kdf_parameters_len",
        "secret_algorithm_len": "secret_parameters_len",
        "key_info_len": "domain_name_len",
    }
    pairs = [(field, partner_of[field], +2) for field in STRING_LENGTH_FIELDS[struct] if field in partner_of]
    for field, partner, delta in pairs:
        field_offset = LENGTH_OFFSETS[struct][field]
        partner_offset = LENGTH_OFFSETS[struct][partner]
        field_original = _u32(base, field_offset)
        partner_original = _u32(base, partner_offset)
        if partner_original - delta < 0:
            continue
        data = _put_u32(base, field_offset, field_original + delta)
        data = _put_u32(data, partner_offset, partner_original - delta)
        cases.append(
            Case(
                struct=struct,
                name="compensated:{}:{}.{}".format(field, partner, index),
                category=BOUNDARY,
                data=data,
                edits=(
                    _edit(field, field_offset, field_original, field_original + delta),
                    _edit(partner, partner_offset, partner_original, partner_original - delta),
                ),
                targeted_field=field,
                description="{} grows +{} into {}, {} shrinks -{}; total length fixed".format(
                    field, delta, partner, partner, delta
                ),
            )
        )
    return cases


def _terminator_case(struct: str, base: bytes, index: int, kind: str) -> Case:
    field = "forest_name" if index % 2 else "domain_name"
    span = field_span(struct, base, field)
    terminator = span.terminator_start
    assert terminator is not None

    if kind == "replace-final-nul":
        data = _replace(base, terminator, span.end, b"A\x00")
        description = "replace the final NUL code unit of {} with 'A'".format(field)
        offset = terminator
    elif kind == "embedded-nul":
        data = _replace(base, span.start, span.start + 2, b"\x00\x00")
        description = (
            "make first code unit of {} NUL while keeping the declared length; the framing is still "
            "distinguishable because the declared length and final NUL both remain"
        ).format(field)
        offset = span.start
    elif kind == "lone-surrogate":
        data = _replace(base, span.start, span.start + 2, b"\x00\xd8")
        description = "first code unit of {} is lone high surrogate U+D800".format(field)
        offset = span.start
    elif kind == "shifted-boundary":
        previous = base[terminator - 2 : terminator]
        data = _replace(base, terminator - 2, terminator, b"\x00\x00")
        data = _replace(data, terminator, span.end, previous)
        description = "move {} boundary one code unit earlier; final real char now sits at the old NUL".format(field)
        offset = terminator - 2
    else:
        raise ValueError("unknown terminator mutation " + kind)

    return Case(
        struct=struct,
        name="term:{}.{}.{}".format(kind, field, index),
        category=TERMINATOR,
        data=data,
        edits=(_edit("{}:{}".format(field, kind), offset, 2, 2),),
        targeted_field=field,
        description=description,
    )


def _boundary_swap(struct: str, base: bytes, index: int) -> Case:
    domain = field_span(struct, base, "domain_name")
    forest = field_span(struct, base, "forest_name")
    assert domain.declared == forest.declared, "seed names must share a byte length"
    domain_bytes = base[domain.start : domain.end]
    forest_bytes = base[forest.start : forest.end]
    data = base[: domain.start] + forest_bytes + base[domain.end : forest.start] + domain_bytes + base[forest.end :]
    return Case(
        struct=struct,
        name="swap-dom-forest.{}".format(index),
        category=BOUNDARY,
        data=data,
        edits=(
            ("domain_name_body", domain.start, len(domain_bytes)),
            ("forest_name_body", forest.start, -len(forest_bytes)),
        ),
        targeted_field="forest_name",
        description="swap UTF-16 bodies of domain_name/forest_name; every length prefix unchanged",
    )


def _flag_cases(struct: str, base: bytes, index: int) -> t.List[Case]:
    flags_offset = 8
    original = _u32(base, flags_offset)
    cases = [
        Case(
            struct=struct,
            name="flags:public-toggle.{}".format(index),
            category=FLAGS,
            data=_put_u32(base, flags_offset, original ^ 1),
            edits=(_edit("flags", flags_offset, original, original ^ 1),),
            targeted_field="flags",
            description="toggle public/private bit 0; all lengths unchanged",
        ),
        Case(
            struct=struct,
            name="flags:all-bits.{}".format(index),
            category=FLAGS,
            data=_put_u32(base, flags_offset, 0xFFFFFFFF),
            edits=(_edit("flags", flags_offset, original, 0xFFFFFFFF),),
            targeted_field="flags",
            description="set every flag bit, including public/private",
        ),
    ]

    if struct == ENVELOPE:
        l2_offset = LENGTH_OFFSETS[struct]["l2_key_len"]
        l2_original = _u32(base, l2_offset)
        public_bits = _u32(base, 60) or 2048
        data = _put_u32(base, flags_offset, original | 1)
        data = _put_u32(data, l2_offset, l2_original + 2)
        cases.append(
            Case(
                struct=struct,
                name="flags:public-l2-mismatch.{}".format(index),
                category=FLAGS,
                data=data,
                edits=(
                    _edit("flags", flags_offset, original, original | 1),
                    _edit("l2_key_len", l2_offset, l2_original, l2_original + 2),
                ),
                targeted_field="l2_key",
                description="public flag set while l2_key is {} bytes for public_key_length {} bits".format(
                    l2_original + 2, public_bits
                ),
            )
        )

    return cases


def _truncation_cases(struct: str, base: bytes) -> t.List[Case]:
    cases = []
    for amount in (1, 2, 3, 7, 8):
        cases.append(
            Case(
                struct=struct,
                name="truncate-{}".format(amount),
                category=TRUNCATION,
                data=base[:-amount],
                edits=(("truncate-tail", len(base) - amount, -amount),),
                targeted_field=None,
                description="drop final {} byte(s) of a legal sample".format(amount),
            )
        )
    cases.append(
        Case(
            struct=struct,
            name="trailing-4",
            category=TRAILING,
            data=base + b"\xde\xad\xbe\xef",
            edits=(("append-tail", len(base), 4),),
            targeted_field=None,
            description="append 4 bytes after the final declared field",
        )
    )
    return cases


def cases_for(struct: str, seed: int = DEFAULT_SEED, count: int = DEFAULT_CASES) -> t.List[Case]:
    """Build the deterministic, size-bounded corpus for one struct."""
    if struct not in STRUCTS:
        raise ValueError("unknown struct " + struct)
    if count < 1:
        raise ValueError("count must be positive")

    _, seed_data = base_sample(struct, 0)
    built: t.List[Case] = [
        Case(
            struct=struct,
            name="seed",
            category=NORMAL,
            data=seed_data,
            targeted_field=None,
            description="unchanged legal pack() output",
        )
    ]
    built.extend(_truncation_cases(struct, seed_data))

    rng = random.Random(seed ^ MASTER_SEED ^ (1 if struct == KEY_IDENTIFIER else 0))
    index = 0
    while len(built) < count:
        index += 1
        _, base = base_sample(struct, index)
        group: t.List[Case] = []
        group.extend(_length_cases(struct, base, index, seed))
        for kind in ("replace-final-nul", "embedded-nul", "lone-surrogate", "shifted-boundary"):
            group.append(_terminator_case(struct, base, index, kind))
        group.append(_boundary_swap(struct, base, index))
        group.extend(_compensated_string_pairs(struct, base, index))
        # Rotate the neutral name swap in and out so each index stays small.
        if index % 3 == 0:
            group.append(_flag_cases(struct, base, index)[0])
        group.extend(_flag_cases(struct, base, index)[1:])
        rng.shuffle(group)
        built.extend(group)

    built = built[:count]
    return [case for case in built if len(case.data) <= MAX_CASE_BYTES][:count]


def all_cases(seed: int = DEFAULT_SEED, count: int = DEFAULT_CASES) -> t.List[Case]:
    return [case for struct in STRUCTS for case in cases_for(struct, seed=seed, count=count)]
