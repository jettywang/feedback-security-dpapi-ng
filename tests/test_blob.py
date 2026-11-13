# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import uuid

import pytest

from dpapi_ng._asn1 import ASN1Reader
from dpapi_ng._blob import (
    BlobParseStrategy,
    DPAPINGBlob,
    EncryptedContentSource,
    SIDDescriptor,
)

from .conftest import get_test_data


def _envelope_end(data: bytes) -> int:
    header = ASN1Reader(data).peek_header()
    return header.tag_length + header.length


def _sample_blob() -> DPAPINGBlob:
    # The shipped test blob is in the LAPS (appended) form.
    return DPAPINGBlob.unpack(get_test_data("dpapi_ng_blob"))


def test_blob_unpack() -> None:
    data = get_test_data("dpapi_ng_blob")

    msg = DPAPINGBlob.unpack(data)
    assert msg.key_identifier.version == 1
    assert msg.key_identifier.flags == 3
    assert msg.key_identifier.is_public_key
    assert msg.key_identifier.l0 == 361
    assert msg.key_identifier.l1 == 16
    assert msg.key_identifier.l2 == 3
    assert msg.key_identifier.root_key_identifier == uuid.UUID("d778c271-9025-9a82-f6dc-b8960b8ad8c5")
    assert msg.key_identifier.key_info == get_test_data("ffc_dh_key")
    assert msg.key_identifier.domain_name == "domain.test"
    assert msg.key_identifier.forest_name == "domain.test"
    assert isinstance(msg.protection_descriptor, SIDDescriptor)
    assert msg.protection_descriptor.value == "S-1-5-21-3337337973-3297078028-437386066-512"
    assert msg.enc_cek == (
        b"\x89\x7F\xC4\x3F\x74\x8E\xFD\x09"
        b"\x57\x27\xDD\xE9\x8F\x4E\x1A\x6F"
        b"\xFB\x9D\x41\x63\xD3\x9F\xB3\x74"
        b"\xD0\x49\xC7\x3D\x89\x69\x0C\x7E"
        b"\xFA\x45\xE6\xBE\x11\x9E\x0D\x6B"
    )
    assert msg.enc_cek_algorithm == "2.16.840.1.101.3.4.1.45"
    assert msg.enc_cek_parameters is None
    assert msg.enc_content == (
        b"\xE4\xCD\xF6\x54\x72\x2A\x49\xD5"
        b"\x5F\x53\x08\x55\x0E\xC4\xE8\xAA"
        b"\xC6\xD0\xBE\x49\x51\x16\xF6\x13"
        b"\x2A\x4D\x59\x17\x9F\xD7\x13\x8E"
        b"\xC9\x4B\x53\x6E\x25\x11\xD5\xCA"
        b"\x0D\x37\x8D\xEC\x3C\x42\x3D\x55"
        b"\xC5\x0A\x60\xDC\x41\x8F\x90\x17"
        b"\x82\x48\x46\xE0\x2B\x62\x04\xC8"
        b"\xB3\x27\x3C\x9F\xC4\x43\x37\x63"
        b"\x94\x47\x3B\xF9\x7B\xDC\x55\x80"
        b"\x09\x51\xAD\xF9\x23\x8D\x8A\x02"
        b"\xFF\xE0\x38\xCD\x4D\x7B\x16\x01"
        b"\x2F\x7A\xE8\xB8\x79\x03\xE0\x50"
        b"\x00\xD8\xE3\x10\xDE\x1B\x2D\x1C"
        b"\xA3\x44\xB2\xF2\x67\x3A\x3D\x5A"
        b"\x5C\x4D\xE4\x63\x26\x4B\x95\x64"
        b"\xEB\x9E\xB0\x4C\x52\x71\x1C\x33"
        b"\xC5\xA7\xA9\x74\x0D\x66\x54\x88"
        b"\x55\xB6"
    )
    assert msg.enc_content_algorithm == "2.16.840.1.101.3.4.1.46"
    assert msg.enc_content_parameters == b"\x30\x11\x04\x0C\x9E\x5B\x2E\x17\xC2\x3F\x04\xFC\x35\x25\xE1\x18\x02\x01\x10"

    # The shipped data carries the content after the envelope (LAPS style).
    assert msg.enc_content_source == EncryptedContentSource.APPENDED


def test_blob_unpack_valid_forms_round_trip() -> None:
    sample = _sample_blob()
    embedded_data = sample.pack(blob_in_envelope=True)
    appended_data = sample.pack(blob_in_envelope=False)

    embedded = DPAPINGBlob.unpack(embedded_data)
    appended = DPAPINGBlob.unpack(appended_data)

    assert embedded.enc_content_source == EncryptedContentSource.EMBEDDED
    assert appended.enc_content_source == EncryptedContentSource.APPENDED
    assert embedded.enc_content == sample.enc_content
    assert appended.enc_content == sample.enc_content
    assert len(appended_data) == _envelope_end(appended_data) + len(sample.enc_content)


@pytest.mark.parametrize("strategy", list(BlobParseStrategy))
def test_blob_unpack_embedded_form(strategy: BlobParseStrategy) -> None:
    embedded_data = _sample_blob().pack(blob_in_envelope=True)

    if strategy == BlobParseStrategy.APPENDED:
        with pytest.raises(ValueError, match="appended"):
            DPAPINGBlob.unpack(embedded_data, strategy)
    else:
        msg = DPAPINGBlob.unpack(embedded_data, strategy)
        assert msg.enc_content_source == EncryptedContentSource.EMBEDDED


@pytest.mark.parametrize("strategy", list(BlobParseStrategy))
def test_blob_unpack_appended_form(strategy: BlobParseStrategy) -> None:
    appended_data = _sample_blob().pack(blob_in_envelope=False)

    if strategy == BlobParseStrategy.EMBEDDED:
        with pytest.raises(ValueError, match="embedded"):
            DPAPINGBlob.unpack(appended_data, strategy)
    else:
        msg = DPAPINGBlob.unpack(appended_data, strategy)
        assert msg.enc_content_source == EncryptedContentSource.APPENDED


def test_blob_unpack_dual_location_conflict() -> None:
    sample = _sample_blob()
    # Embedded content in the envelope plus a raw copy appended after it.
    dual_data = sample.pack(blob_in_envelope=True) + sample.enc_content

    for strategy in BlobParseStrategy:
        with pytest.raises(ValueError, match="ambiguous|second complete|unexpected trailing|as well as"):
            DPAPINGBlob.unpack(dual_data, strategy)


def test_blob_unpack_empty_content_with_garbage() -> None:
    sample = _sample_blob()
    appended_data = sample.pack(blob_in_envelope=False)
    envelope_only = appended_data[: _envelope_end(appended_data)]
    garbage = b"\xDE\xAD\xBE\xEF"
    garbage_data = envelope_only + garbage

    auto = DPAPINGBlob.unpack(garbage_data, BlobParseStrategy.AUTO)
    appended = DPAPINGBlob.unpack(garbage_data, BlobParseStrategy.APPENDED)
    assert auto.enc_content_source == EncryptedContentSource.APPENDED
    assert auto.enc_content == garbage
    assert appended.enc_content == garbage

    with pytest.raises(ValueError, match="embedded"):
        DPAPINGBlob.unpack(garbage_data, BlobParseStrategy.EMBEDDED)


def test_blob_unpack_no_content_anywhere() -> None:
    sample = _sample_blob()
    appended_data = sample.pack(blob_in_envelope=False)
    envelope_only = appended_data[: _envelope_end(appended_data)]

    for strategy in BlobParseStrategy:
        with pytest.raises(ValueError, match="no encrypted content|requires"):
            DPAPINGBlob.unpack(envelope_only, strategy)


@pytest.mark.parametrize("cut", [0, 1, 5])
def test_blob_unpack_truncated_header(cut: int) -> None:
    data = _sample_blob().pack(blob_in_envelope=False)
    with pytest.raises(ValueError, match="truncated"):
        DPAPINGBlob.unpack(data[:cut])


def test_blob_unpack_truncated_envelope_body() -> None:
    data = _sample_blob().pack(blob_in_envelope=False)
    with pytest.raises(ValueError, match="truncated"):
        DPAPINGBlob.unpack(data[: _envelope_end(data) - 3])


def test_blob_unpack_second_envelope_rejected() -> None:
    sample = _sample_blob()
    appended_data = sample.pack(blob_in_envelope=False)
    empty_envelope = appended_data[: _envelope_end(appended_data)]
    # A complete second CMS envelope (with its own embedded content) appended.
    second_envelope = empty_envelope + sample.pack(blob_in_envelope=True)

    for strategy in BlobParseStrategy:
        with pytest.raises(ValueError, match="second complete CMS EnvelopedData"):
            DPAPINGBlob.unpack(second_envelope, strategy)


def test_blob_unpack_invalid_strategy() -> None:
    data = _sample_blob().pack(blob_in_envelope=True)
    with pytest.raises(ValueError, match="BlobParseStrategy"):
        DPAPINGBlob.unpack(data, "strict")  # type: ignore[arg-type]

