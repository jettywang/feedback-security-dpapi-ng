"""Outcome classification and minimal-reproducer shrinking.

The oracle never treats "unpack then pack equal" as proof of correctness. It
combines three independent signals:

* the independent layout (:mod:`tests.fuzz.layout`) for structural truth;
* the parser's success/failure and exception class, for the abnormal contract;
* field-level comparison of parsed values against the inspector's slices.

A layout-valid sample that fails is a rejection; a layout-invalid sample that
succeeds is a silent acceptance. Both are reported with the actual value the
parser produced and the field/offset where the inspector disagrees.
"""

from __future__ import annotations

import dataclasses
import typing as t
import uuid

from dpapi_ng import _blob as blob
from dpapi_ng import _gkdi as gkdi

from . import corpus
from . import layout as layout_mod

STRUCT_CLASSES: t.Dict[str, t.Any] = {
    corpus.ENVELOPE: gkdi.GroupKeyEnvelope,
    corpus.KEY_IDENTIFIER: blob.KeyIdentifier,
}

HEADER_OFFSETS = {
    "version": 0,
    "flags": 8,
    "l0": 12,
    "l1": 16,
    "l2": 20,
    "root_key_identifier": 24,
}

# Contract classification for abnormal samples. ``malformed-input`` is what a
# strict parser should raise for a structure the layout inspector already
# rejects; ``internal-parser-fault`` means the parser crashed in a way that
# leaks an implementation detail (Guid/UUID construction, codec, or stdlib)
# rather than reporting the struct's field and offset.
MALFORMED_INPUT_EXCEPTIONS = (ValueError,)
INTERNAL_FAULT_EXCEPTIONS = (IndexError, KeyError, TypeError, AttributeError, MemoryError, OverflowError)

STRUCT_FIELDS = {
    corpus.ENVELOPE: (
        "version",
        "flags",
        "l0",
        "l1",
        "l2",
        "root_key_identifier",
        "kdf_algorithm",
        "kdf_parameters",
        "secret_algorithm",
        "secret_parameters",
        "private_key_length",
        "public_key_length",
        "domain_name",
        "forest_name",
        "l1_key",
        "l2_key",
    ),
    corpus.KEY_IDENTIFIER: (
        "version",
        "flags",
        "l0",
        "l1",
        "l2",
        "root_key_identifier",
        "key_info",
        "domain_name",
        "forest_name",
    ),
}


@dataclasses.dataclass(frozen=True)
class FieldDiff:
    field: str
    expected: t.Any
    actual: t.Any
    offset: int

    def render(self) -> str:
        return "field {!r} at offset {}: independent slice {!r}, parser produced {!r}".format(
            self.field, self.offset, self.expected, self.actual
        )


@dataclasses.dataclass(frozen=True)
class Outcome:
    struct: str
    case_name: str
    category: str
    accepted: bool
    exception_class: t.Optional[str]
    exception_message: str
    deviation: t.Optional[str]
    deviation_field: t.Optional[str]
    checkpoint: int
    illegal: bool
    diffs: t.Tuple[FieldDiff, ...] = ()
    notes: t.Tuple[str, ...] = ()
    span_start: t.Optional[int] = None

    def layout_invalid(self) -> bool:
        """True when the independent inspector rejects the input layout.

        This is distinct from ``illegal``: a hardened parser may reject a
        layout-invalid sample, so ``illegal`` (accepted *and* invalid) would
        be False even though the input itself is structurally impossible.
        """
        return self.deviation is not None

    def rejected_by_layout(self) -> bool:
        return self.layout_invalid() and not self.accepted

    def contract_class(self) -> str:
        """One of: ok, ambiguous_acceptance, interpretation_mismatch,
        silent_acceptance, rejected_malformed, rejected_codec, false_rejection,
        parser_crash."""
        if self.accepted:
            if self.illegal:
                # An embedded NUL inside a fixed-length UTF-16 field is
                # framed by its declared length and trailing NUL, so a parser
                # may legitimately preserve it as part of the name. Treat it
                # as ambiguous only when that is the sole layout deviation.
                if self.deviation == "early_terminator" and not self.diffs:
                    return "ambiguous_acceptance"
                return "silent_acceptance"
            if self.diffs:
                return "interpretation_mismatch"
            return "ok"
        if self.deviation is None:
            return "false_rejection"
        if self.exception_class == "UnicodeDecodeError":
            return "rejected_codec"
        try:
            exception_type = _resolve_exception(self.exception_class)
        except Exception:  # pragma: nocover
            return "parser_crash"
        if issubclass(exception_type, ValueError):
            return "rejected_malformed"
        return "parser_crash"

    def summary(self) -> str:
        return "{} accepted={} exception={} deviation={} field={} checkpoint={} diffs={}".format(
            self.case_name,
            self.accepted,
            self.exception_class or "-",
            self.deviation or "-",
            self.deviation_field or "-",
            self.checkpoint,
            len(self.diffs),
        )


def _resolve_exception(name: t.Optional[str]) -> t.Type[BaseException]:
    if name is None:
        raise LookupError("no exception recorded")
    builtins_map = __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)
    return t.cast(t.Type[BaseException], builtins_map[name])


def _field_start(layout: layout_mod.Layout) -> t.Optional[int]:
    if layout.field is None:
        return None
    span = layout.field_span(layout.field)
    return span.start if span is not None else None


def _safe_equal(expected: t.Any, actual: t.Any) -> bool:
    try:
        return bool(expected == actual)
    except Exception:  # pragma: nocover - defensive for exotic values
        return False


def header_diffs(struct: str, data: bytes, parsed: t.Any, layout: layout_mod.Layout) -> t.List[FieldDiff]:
    header = layout.header
    if header is None:
        return []
    diffs: t.List[FieldDiff] = []
    expected = {
        "version": header.version,
        "flags": header.flags,
        "l0": header.l0,
        "l1": header.l1,
        "l2": header.l2,
        "root_key_identifier": uuid.UUID(bytes_le=header.root_key_identifier),
    }
    for name, value in expected.items():
        if not _safe_equal(value, getattr(parsed, name, None)):
            diffs.append(FieldDiff(name, value, getattr(parsed, name, None), HEADER_OFFSETS[name]))
    return diffs


def value_diffs(struct: str, data: bytes, parsed: t.Any, layout: layout_mod.Layout) -> t.List[FieldDiff]:
    diffs = header_diffs(struct, data, parsed, layout)
    for span in layout.spans:
        actual = getattr(parsed, span.name, None)
        if not _safe_equal(span.value, actual):
            diffs.append(FieldDiff(span.name, span.value, actual, span.start))
    return diffs


def run_case(case: corpus.Case) -> Outcome:
    data = case.data
    struct_class: t.Any = STRUCT_CLASSES[case.struct]
    layout = corpus.inspector(case.struct, data)

    parsed: t.Any = None
    exception: t.Optional[BaseException] = None
    try:
        parsed = struct_class.unpack(data)
    except Exception as exc:  # parser contract is "raise"; classify the class
        exception = exc

    accepted = parsed is not None
    exception_class = None
    exception_message = ""
    if exception is not None:
        exception_class = type(exception).__name__
        exception_message = str(exception)

    illegal = accepted and not layout.is_valid
    diffs: t.List[FieldDiff] = []
    if accepted and layout.is_valid:
        diffs = value_diffs(case.struct, data, parsed, layout)

    notes: t.List[str] = []
    if accepted and layout.is_valid and diffs:
        notes.append("parsed values disagree with the independent slices")
    if exception is not None and layout.is_valid:
        notes.append("well-formed layout was rejected")

    outcome = Outcome(
        struct=case.struct,
        case_name=case.label(),
        category=case.category,
        accepted=accepted,
        exception_class=exception_class,
        exception_message=exception_message,
        deviation=layout.deviation,
        deviation_field=layout.field,
        checkpoint=layout.checkpoint,
        illegal=illegal,
        diffs=tuple(diffs),
        notes=tuple(notes),
        span_start=_field_start(layout),
    )
    # Round-trip is a supplementary property: it must hold for a sample the
    # independent layout and value comparison both already accepted.
    if accepted and layout.is_valid and not diffs and parsed.pack() != data:
        outcome = dataclasses.replace(
            outcome,
            diffs=tuple(diffs) + (FieldDiff("packed_bytes", data, parsed.pack(), 0),),
            notes=outcome.notes + ("re-pack is not byte-identical to the input",),
        )
    return outcome


@dataclasses.dataclass(frozen=True)
class Reproducer:
    """A minimized input plus the offsets needed to replay it."""

    struct: str
    category: str
    original_name: str
    data: bytes
    original_size: int
    exception_class: t.Optional[str]
    deviation: t.Optional[str]
    deviation_field: t.Optional[str]
    checkpoint: int
    diffs: t.Tuple[FieldDiff, ...]

    def label(self) -> str:
        return "{}:{}".format(self.struct, self.category)

    def explain(self) -> str:
        parts = [
            "{} -> {} bytes (from {})".format(self.label(), len(self.data), self.original_size),
            "checkpoint offset {}".format(self.checkpoint),
        ]
        if self.exception_class:
            parts.append("exception {}".format(self.exception_class))
        if self.deviation:
            parts.append("layout {} in {}".format(self.deviation, self.deviation_field))
        for diff in self.diffs:
            parts.append(diff.render())
        return "; ".join(parts)


def outcome_signature(outcome: Outcome) -> t.Tuple[t.Any, ...]:
    """Identity of a fault, used to keep a reproducer faithful.

    The shrinker may only remove bytes while this signature is unchanged, so a
    minimized input still exhibits the same deviation, in the same field, with
    the same exception class or the same silent acceptance.
    """
    diff_fields = tuple(diff.field for diff in outcome.diffs)
    return (
        outcome.struct,
        outcome.accepted,
        outcome.exception_class,
        outcome.deviation,
        outcome.deviation_field,
        diff_fields,
    )


def _still_fails(struct: str, data: bytes, predicate: t.Callable[[Outcome], bool]) -> t.Optional[Outcome]:
    case = corpus.Case(struct=struct, name="shrink", category="shrink", data=bytes(data))
    outcome = run_case(case)
    return outcome if predicate(outcome) else None


def shrink(
    struct: str,
    data: bytes,
    predicate: t.Callable[[Outcome], bool],
    max_rounds: int = 64,
    max_attempts: int = 400,
) -> t.Tuple[bytes, t.Optional[Outcome]]:
    """Delete byte ranges while preserving the outcome class.

    Only whole-tail truncation of the final field and zero-length-preserving
    deletions from the *body* end of the buffer are attempted, and the loop is
    bounded. This keeps reproducers small without inventing a different
    layout than the bug being reported.
    """
    best = bytes(data)
    best_outcome = _still_fails(struct, best, predicate)
    attempts = 0
    rounds = 0

    while best_outcome is not None and len(best) > 0 and rounds < max_rounds and attempts < max_attempts:
        rounds += 1
        changed = False
        for chunk in (16, 8, 4, 2, 1):
            if len(best) <= chunk or attempts >= max_attempts:
                continue
            attempts += 1
            candidate = best[:-chunk]
            outcome = _still_fails(struct, candidate, predicate)
            if outcome is not None:
                best = candidate
                best_outcome = outcome
                changed = True
                break
        if not changed:
            break

    return best, best_outcome


def make_reproducer(
    case: corpus.Case, predicate: t.Callable[[Outcome], bool] = lambda o: o.layout_invalid()
) -> t.Optional[Reproducer]:
    original = run_case(case)
    if not predicate(original):
        return None
    signature = outcome_signature(original)

    def same_fault(candidate: Outcome) -> bool:
        return predicate(candidate) and outcome_signature(candidate) == signature

    minimized, outcome = shrink(case.struct, case.data, same_fault)
    assert outcome is not None
    return Reproducer(
        struct=case.struct,
        category=case.category,
        original_name=case.label(),
        data=minimized,
        original_size=len(case.data),
        exception_class=outcome.exception_class,
        deviation=outcome.deviation,
        deviation_field=outcome.deviation_field,
        checkpoint=outcome.checkpoint,
        diffs=outcome.diffs,
    )
