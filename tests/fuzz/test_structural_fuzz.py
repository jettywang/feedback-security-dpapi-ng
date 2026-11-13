# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Structural fuzzing for GroupKeyEnvelope / KeyIdentifier.

The suite is deterministic (fixed seed, fixed case count, fixed byte cap).
It checks three things independently of ``pack() == input``:

* legal samples round-trip byte-for-byte;
* malformed samples fail with a classified exception, and the exception
  carries the offending field and input offset;
* the independent layout inspector never sees a field overrun or a
  boundary violation in a sample the parser accepted.
"""

from __future__ import annotations

import base64
import json
import pathlib
import typing

import pytest

from dpapi_ng import _blob as blob
from dpapi_ng import _gkdi as gkdi

from . import corpus, layout, oracle

FINDINGS_PATH = pathlib.Path(__file__).parent / "findings.json"

_STRUCT_CLASS: dict[str, typing.Any] = {
    corpus.ENVELOPE: gkdi.GroupKeyEnvelope,
    corpus.KEY_IDENTIFIER: blob.KeyIdentifier,
}


def _load_findings() -> dict:
    with FINDINGS_PATH.open(encoding="utf-8") as fd:
        return json.load(fd)


def _repr_bytes(data: bytes) -> str:
    return "0x" + data.hex()


@pytest.fixture(scope="module")
def all_cases() -> list[corpus.Case]:
    return corpus.all_cases()


@pytest.fixture(scope="module")
def outcomes(all_cases: list[corpus.Case]) -> list[oracle.Outcome]:
    return [oracle.run_case(case) for case in all_cases]


@pytest.mark.parametrize("struct", corpus.STRUCTS)
def test_layout_inspector_slices_legal_pack(struct: str) -> None:
    """The inspector must agree with pack() on the physical field order."""
    value, data = corpus.base_sample(struct)
    inspected = corpus.inspector(struct, data)

    assert inspected.is_valid, inspected.explain()
    assert inspected.consumed_end == len(data)
    assert not inspected.overlaps()

    spans = {span.name: span for span in inspected.spans}
    if struct == corpus.ENVELOPE:
        assert isinstance(value, gkdi.GroupKeyEnvelope)
        expected = {
            "kdf_algorithm": value.kdf_algorithm,
            "kdf_parameters": value.kdf_parameters,
            "secret_algorithm": value.secret_algorithm,
            "secret_parameters": value.secret_parameters,
            "domain_name": value.domain_name,
            "forest_name": value.forest_name,
            "l1_key": value.l1_key,
            "l2_key": value.l2_key,
        }
    else:
        assert isinstance(value, blob.KeyIdentifier)
        expected = {
            "key_info": value.key_info,
            "domain_name": value.domain_name,
            "forest_name": value.forest_name,
        }
    for name, expected_value in expected.items():
        assert spans[name].value == expected_value, f"{name} slice did not match the packed value"


@pytest.mark.parametrize("struct", corpus.STRUCTS)
def test_layout_inspector_detects_known_offsets(struct: str) -> None:
    """Pin the documented header sizes and field offsets."""
    _, data = corpus.base_sample(struct)
    header_size = 80 if struct == corpus.ENVELOPE else 52
    assert corpus.inspector(struct, data).spans[0].start == header_size

    fields = [(name, offset) for offset, name in corpus.HEADER_NAMES[struct].items() if name.endswith("_len")]
    for name, offset in fields:
        inspected = corpus.inspector(struct, data)
        span = inspected.field_span(name.replace("_len", ""))
        assert span is not None
        assert span.declared == int.from_bytes(data[offset : offset + 4], "little")
        assert span.terminator_start is not None or span.kind == "bytes"


@pytest.mark.parametrize("struct", corpus.STRUCTS)
def test_normal_samples_round_trip(struct: str) -> None:
    """Legal pack() output must parse and re-pack to identical bytes."""
    expected_fields = {
        "version": 1,
    }
    for case in corpus.cases_for(struct, count=corpus.DEFAULT_CASES):
        if case.category != corpus.NORMAL:
            continue
        outcome = oracle.run_case(case)
        assert outcome.contract_class() == "ok", outcome.summary()
        assert not outcome.diffs
        parsed = _STRUCT_CLASS[struct].unpack(case.data)
        assert parsed.pack() == case.data
        for name, expected in expected_fields.items():
            assert getattr(parsed, name) == expected


def test_legal_variants_round_trip() -> None:
    """Empty and non-ASCII names exercise UTF-16 framing within legal bounds."""
    variants = (
        ("", ""),
        ("fuzz.invalid", ""),
        ("例え.invalid", "Ω.invalid"),
        ("\U0001f600.invalid", "x.invalid"),
    )
    for domain, forest in variants:
        envelope = corpus.envelope_struct(0)
        object.__setattr__(envelope, "domain_name", domain)
        object.__setattr__(envelope, "forest_name", forest)
        data = envelope.pack()
        assert layout.inspect_envelope(data).is_valid
        assert gkdi.GroupKeyEnvelope.unpack(data).pack() == data

        identifier = corpus.key_identifier_struct(0)
        object.__setattr__(identifier, "domain_name", domain)
        object.__setattr__(identifier, "forest_name", forest)
        data = identifier.pack()
        assert layout.inspect_key_identifier(data).is_valid
        assert blob.KeyIdentifier.unpack(data).pack() == data


def test_corpus_is_deterministic_and_bounded() -> None:
    first = corpus.all_cases()
    second = corpus.all_cases()

    assert len(first) == len(second) == len(corpus.STRUCTS) * corpus.DEFAULT_CASES
    assert [case.data for case in first] == [case.data for case in second]
    assert [case.name for case in first] == [case.name for case in second]
    assert all(len(case.data) <= corpus.MAX_CASE_BYTES for case in first)
    assert len({(case.struct, case.name) for case in first}) == len(first)

    # Different seeds must actually change the sample order/rotation while
    # keeping the same categories and byte budget.
    other = corpus.all_cases(seed=corpus.DEFAULT_SEED ^ 0xABCDEF)
    assert len(other) == len(first)
    assert [case.data for case in other] != [case.data for case in first]


def test_corpus_covers_every_field_and_category() -> None:
    cases = corpus.all_cases()
    covered_fields = {case.targeted_field for case in cases if case.targeted_field}
    covered_categories = {case.category for case in cases}

    assert set(corpus.CATEGORIES) <= covered_categories
    for struct in corpus.STRUCTS:
        for name in corpus.ALL_LENGTH_FIELDS[struct]:
            assert name in covered_fields, f"{name} has no length-prefix case"
    assert "domain_name" in covered_fields
    assert "forest_name" in covered_fields
    assert "flags" in covered_fields


def test_normal_samples_have_no_deviation(all_cases: list[corpus.Case]) -> None:
    for case in all_cases:
        if case.category != corpus.NORMAL:
            continue
        inspected = corpus.inspector(case.struct, case.data)
        assert inspected.is_valid, f"{case.label()}: {inspected.explain()}"
        assert not inspected.overlaps()


def test_malformed_samples_are_classified_not_silently_accepted(outcomes: list[oracle.Outcome]) -> None:
    """Every case must land in a named class, never a bare acceptance.

    Layout-valid cases (name swaps, flag-only edits, scalar metadata) belong to
    ``ok`` because they do not violate field framing. The distinguishing check
    is that no *layout-invalid* case is silently accepted.
    """
    unexpected = []
    for outcome in outcomes:
        cls = outcome.contract_class()
        if cls == "silent_acceptance" or cls == "interpretation_mismatch":
            unexpected.append(outcome.summary())
        elif outcome.deviation is not None and cls == "ok":
            unexpected.append("layout-invalid but classed ok: " + outcome.summary())
        elif outcome.deviation is None and cls == "rejected_malformed":
            unexpected.append("well-formed but classed rejected: " + outcome.summary())

    assert not unexpected, "malformed inputs were not classified:\n" + "\n".join(unexpected)


def test_malformed_rejection_messages_include_field_and_offset(outcomes: list[oracle.Outcome]) -> None:
    checked = 0
    for outcome in outcomes:
        if outcome.contract_class() != "rejected_malformed":
            continue
        checked += 1
        message = outcome.exception_message
        field = outcome.deviation_field
        assert field is None or field in message
        offsets = {outcome.checkpoint}
        if outcome.span_start is not None:
            offsets.add(outcome.span_start)
        assert any(str(offset) in message for offset in offsets) or outcome.deviation == "trailing_bytes"
    assert checked >= len(outcomes) // 2, "not enough malformed samples were rejected"


def test_no_outcome_is_a_parser_crash(outcomes: list[oracle.Outcome]) -> None:
    crashes = [
        outcome.summary() for outcome in outcomes if outcome.contract_class() in ("parser_crash", "false_rejection")
    ]
    assert not crashes, "parser crashed or rejected a well-formed layout:\n" + "\n".join(crashes)


def test_corpus_never_accepts_an_overrun_layout(outcomes: list[oracle.Outcome]) -> None:
    """Independent check: nothing with an impossible layout may be accepted."""
    offenders = []
    for outcome in outcomes:
        if outcome.accepted and outcome.deviation in ("length_overrun", "bad_terminator", "short_string", "odd_utf16"):
            offenders.append(outcome.summary())
    assert not offenders, "parser accepted spanning/invalid layouts:\n" + "\n".join(offenders)


def test_shrinker_preserves_fault_identity() -> None:
    case = next(
        case
        for case in corpus.cases_for(corpus.ENVELOPE)
        if case.category == corpus.LENGTH_PREFIX
        and case.targeted_field in ("kdf_parameters_len", "l2_key_len")
        and oracle.run_case(case).layout_invalid()
    )
    original = oracle.run_case(case)
    assert original.layout_invalid()

    reproducer = oracle.make_reproducer(case)
    assert reproducer is not None
    assert len(reproducer.data) <= len(case.data)
    assert reproducer.deviation == original.deviation
    assert reproducer.deviation_field == original.deviation_field

    minimized_layout = corpus.inspector(corpus.ENVELOPE, reproducer.data)
    assert minimized_layout.deviation == original.deviation
    # The checkpoint must point into the minimized buffer, not the original.
    assert 0 <= reproducer.checkpoint <= len(reproducer.data)

    with pytest.raises(ValueError) as exc:
        gkdi.GroupKeyEnvelope.unpack(reproducer.data)
    message = str(exc.value)
    expected = original.deviation_field or original.deviation or ""
    assert expected in message


def test_findings_manifest_records_baseline_interpretation() -> None:
    """Regression anchors: each recorded witness must still be rejected."""
    manifest = _load_findings()
    assert manifest["seed"] == corpus.DEFAULT_SEED

    for record in manifest["records"]:
        data = base64.b64decode(record["data_base64"])
        struct = record["struct"]
        inspected = corpus.inspector(struct, data)

        assert len(data) == record["minimized_size"]
        assert record["minimized_size"] <= record["original_size"]
        assert inspected.is_valid is False
        assert inspected.deviation == record["inspector"]["deviation"]
        assert inspected.field == record["inspector"]["field"]
        assert inspected.checkpoint == record["checkpoint"]

        with pytest.raises(ValueError) as exc:
            _STRUCT_CLASS[struct].unpack(data)
        message = str(exc.value)
        field = record["inspector"]["field"]
        assert field is None or field in message
        offsets = {str(record["checkpoint"])}
        span_start = record["inspector"].get("span_start")
        if span_start is not None:
            offsets.add(str(span_start))
        assert any(offset in message for offset in offsets) or record["inspector"]["deviation"] == "trailing_bytes"


def test_findings_manifest_digits_the_same_interpretation_difference() -> None:
    """The manifest states what the baseline parser actually produced."""
    manifest = _load_findings()
    record = next(r for r in manifest["records"] if r["id"] == "key_identifier:length_prefix")

    difference = record["baseline"]["interpretation"]
    assert record["baseline"]["accepted"] is True
    # This witness is a terminated-name boundary overrun: the baseline
    # accepted it, the inspector says the name's final code unit is not NUL.
    assert difference["domain_name"].startswith("'alpha-")
    assert record["inspector"]["deviation"] == "bad_terminator"
