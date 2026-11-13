# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
"""Independent, recomputable GKDI derivation interop tests.

These tests check the boundary between Python protocol values and the exact
on-the-wire byte representation consumed by MS-GKDI. Every expected byte
string and every derived key is produced by the short, self-contained
``_ref_*`` reference functions in this module. The reference deliberately does
not call the code under test - in particular it never invokes
:meth:`dpapi_ng._gkdi.GetKey.pack`, :meth:`dpapi_ng._gkdi.GroupKeyEnvelope.pack`
or :func:`dpapi_ng._gkdi.compute_kdf_context` - so the assertions are an
independent recomputation rather than a re-encoding of the same logic.

Only protocol interoperability is exercised: the data used are the public
vectors shipped under ``tests/data`` plus synthetic root keys / indices. No
real protected data is involved.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import typing as t
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

import dpapi_ng
from dpapi_ng._blob import DPAPINGBlob, KeyIdentifier
from dpapi_ng._crypto import content_decrypt
from dpapi_ng._gkdi import (
    ECDHKey,
    FFCDHKey,
    FFCDHParameters,
    GetKey,
    GroupKeyEnvelope,
    KDFParameters,
    compute_kdf_context,
)

from .conftest import get_test_data


# ---------------------------------------------------------------------------
# Independent reference implementation
#
# Only the Python standard library (struct/hashlib/hmac/uuid) and the raw
# cryptographic primitives (ECDH agreement, AES key unwrap) are used. None of
# the dpapi_ng pack/compute_kdf_context helpers are referenced here.
# ---------------------------------------------------------------------------

KDS_LABEL = "KDS service\0".encode("utf-16-le")
KDS_PUBLIC_KEY_CONTEXT = "KDS public key\0".encode("utf-16-le")
ALGORITHM_ID_SHA512 = "SHA512\0".encode("utf-16-le")

_HASH_NAME = {"SHA1": "sha1", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512"}
_HASH_SIZE = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
_CURVE_HASH = {"P256": "sha256", "P384": "sha384", "P521": "sha512"}
_CURVE = {"P256": ec.SECP256R1(), "P384": ec.SECP384R1(), "P521": ec.SECP521R1()}

# Hard-coded expected wire bytes, recomputed independently with struct/uuid
# (see the individual tests for the matching human-readable value).
WIRE_GUID_MIXED_ENDIAN = bytes.fromhex("204429737f916a419ec386082afafb9e")
WIRE_GUID_BIG_ENDIAN = bytes.fromhex("73294420917f416a9ec386082afafb9e")
WIRE_KDS_LABEL = bytes.fromhex("4b0044005300200073006500720076006900630065000000")
WIRE_PUBLIC_KEY_CONTEXT = bytes.fromhex(
    "4b004400530020007000750062006c006900630020006b00650079000000"
)
WIRE_ALGORITHM_ID_SHA512 = bytes.fromhex("5300480041003500310032000000")


def _ref_guid_bytes_le(value: uuid.UUID) -> bytes:
    """Mixed-endian GUID encoding used by NDR (Data1/Data2/Data3 swapped)."""
    time_low, time_mid, time_hi, clock_hi, clock_low, node = value.fields
    clock_seq = (clock_hi << 8) | clock_low
    return (
        struct.pack("<IHH", time_low, time_mid, time_hi)
        + struct.pack(">H", clock_seq)
        + node.to_bytes(6, byteorder="big")
    )


def _ref_signed_long(value: int) -> bytes:
    """A signed 32-bit NDR ``LONG`` in little-endian."""
    return struct.pack("<l", value)


def _ref_utf16_terminated(value: str) -> bytes:
    """A UTF-16-LE string including its single wide NUL terminator."""
    return (value + "\0").encode("utf-16-le")


def _ref_kdf_context(key_guid: uuid.UUID, l0: int, l1: int, l2: int) -> bytes:
    """RKID || L0 || L1 || L2 as it appears in the KDF context."""
    return (
        _ref_guid_bytes_le(key_guid)
        + _ref_signed_long(l0)
        + _ref_signed_long(l1)
        + _ref_signed_long(l2)
    )


def _ref_sp800_108(hash_name: str, key: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """NIST SP800-108 counter-mode HMAC KDF (rlen/llen = 4, counter first)."""
    fixed_input = label + b"\x00" + context + (length * 8).to_bytes(4, byteorder="big")
    output = b""
    counter = 1
    while len(output) < length:
        output += hmac.new(
            key,
            counter.to_bytes(4, byteorder="big") + fixed_input,
            hash_name,
        ).digest()
        counter += 1
    return output[:length]


def _ref_concat_kdf(hash_name: str, shared: bytes, other_info: bytes, length: int) -> bytes:
    """NIST SP800-56A single-step (Concat) KDF, hash-only variant."""
    output = b""
    counter = 1
    while len(output) < length:
        output += hashlib.new(
            hash_name,
            counter.to_bytes(4, byteorder="big") + shared + other_info,
        ).digest()
        counter += 1
    return output[:length]


def _ref_l1_key(
    hash_name: str,
    target_sd: bytes,
    root_key_id: uuid.UUID,
    l0: int,
    root_key: bytes,
) -> bytes:
    l0_seed = _ref_sp800_108(
        hash_name,
        root_key,
        KDS_LABEL,
        _ref_kdf_context(root_key_id, l0, -1, -1),
        64,
    )
    return _ref_sp800_108(
        hash_name,
        l0_seed,
        KDS_LABEL,
        _ref_kdf_context(root_key_id, l0, 31, -1) + target_sd,
        64,
    )


def _ref_l2_key(
    hash_name: str,
    root_key_id: uuid.UUID,
    l0: int,
    request_l1: int,
    request_l2: int,
    l1: int,
    l1_key: bytes,
    l2: int,
    l2_key: bytes,
) -> bytes:
    reseed_l2 = l2 == 31 or l1 != request_l1
    if l2 != 31 and l1 != request_l1:
        l1 -= 1

    while l1 != request_l1:
        reseed_l2 = True
        l1 -= 1
        l1_key = _ref_sp800_108(
            hash_name,
            l1_key,
            KDS_LABEL,
            _ref_kdf_context(root_key_id, l0, l1, -1),
            64,
        )

    if reseed_l2:
        l2 = 31
        l2_key = _ref_sp800_108(
            hash_name,
            l1_key,
            KDS_LABEL,
            _ref_kdf_context(root_key_id, l0, l1, l2),
            64,
        )

    while l2 != request_l2:
        l2 -= 1
        l2_key = _ref_sp800_108(
            hash_name,
            l2_key,
            KDS_LABEL,
            _ref_kdf_context(root_key_id, l0, l1, l2),
            64,
        )

    return l2_key


def _ref_l2_key_with_guid_wire(
    hash_name: str,
    guid_wire: bytes,
    l0: int,
    request_l1: int,
    request_l2: int,
    l1: int,
    l1_key: bytes,
    l2: int,
    l2_key: bytes,
) -> bytes:
    """L2 key derivation with the RKID wire bytes supplied explicitly."""
    def context(level_0: int, level_1: int, level_2: int) -> bytes:
        return guid_wire + _ref_signed_long(level_0) + _ref_signed_long(level_1) + _ref_signed_long(level_2)

    reseed_l2 = l2 == 31 or l1 != request_l1
    if l2 != 31 and l1 != request_l1:
        l1 -= 1

    while l1 != request_l1:
        reseed_l2 = True
        l1 -= 1
        l1_key = _ref_sp800_108(hash_name, l1_key, KDS_LABEL, context(l0, l1, -1), 64)

    if reseed_l2:
        l2 = 31
        l2_key = _ref_sp800_108(hash_name, l1_key, KDS_LABEL, context(l0, l1, l2), 64)

    while l2 != request_l2:
        l2 -= 1
        l2_key = _ref_sp800_108(hash_name, l2_key, KDS_LABEL, context(l0, l1, l2), 64)

    return l2_key


def _ref_l1_key_with_guid_wire(
    hash_name: str,
    target_sd: bytes,
    guid_wire: bytes,
    l0: int,
    root_key: bytes,
) -> bytes:
    """L1 seed derivation with the RKID wire bytes supplied explicitly.

    This mirrors :func:`_ref_l1_key` but lets a caller substitute the GUID
    encoding (used by the byte-order mutation test) without touching any
    pack helper from the code under test.
    """
    l0_seed = _ref_sp800_108(
        hash_name,
        root_key,
        KDS_LABEL,
        guid_wire + _ref_signed_long(l0) + _ref_signed_long(-1) + _ref_signed_long(-1),
        64,
    )
    return _ref_sp800_108(
        hash_name,
        l0_seed,
        KDS_LABEL,
        guid_wire + _ref_signed_long(l0) + _ref_signed_long(31) + _ref_signed_long(-1) + target_sd,
        64,
    )


def _ref_unpack_ffc_dh_key(data: bytes) -> t.Tuple[int, int, int, int]:
    """Minimal FFC DH key struct reader (magic DHPB, big-endian integers)."""
    assert data[:4] == b"\x44\x48\x50\x42"
    key_length = struct.unpack("<I", data[4:8])[0]
    offset = 8
    field_order = int.from_bytes(data[offset : offset + key_length], "big")
    offset += key_length
    generator = int.from_bytes(data[offset : offset + key_length], "big")
    offset += key_length
    public_key = int.from_bytes(data[offset : offset + key_length], "big")
    return key_length, field_order, generator, public_key


def _ref_unpack_ecdh_key(data: bytes) -> t.Tuple[str, int, int, int]:
    """Minimal ECDH key struct reader (magic ECK1/3/5, big-endian coords)."""
    curve_id = struct.unpack("<I", data[:4])[0]
    curve = {0x314B4345: "P256", 0x334B4345: "P384", 0x354B4345: "P521"}[curve_id]
    key_length = struct.unpack("<I", data[4:8])[0]
    x = int.from_bytes(data[8 : 8 + key_length], "big")
    y = int.from_bytes(data[8 + key_length : 8 + 2 * key_length], "big")
    return curve, key_length, x, y


def _ref_kek(
    hash_name: str,
    l2_key: bytes,
    key_identifier: KeyIdentifier,
    secret_algorithm: str,
    private_key_length: int,
) -> bytes:
    if not key_identifier.is_public_key:
        # Nonce branch: KDF(L2, "KDS service", key_info, 256).
        return _ref_sp800_108(hash_name, l2_key, KDS_LABEL, key_identifier.key_info, 32)

    # Public key branch: derive an ephemeral private key, perform the secret
    # agreement, run SP800-56A Concat, then the final SP800-108 step.
    private_key = _ref_sp800_108(
        hash_name,
        l2_key,
        KDS_LABEL,
        _ref_utf16_terminated(secret_algorithm),
        private_key_length,
    )

    if secret_algorithm == "DH":
        key_length, field_order, _generator, peer_public = _ref_unpack_ffc_dh_key(
            key_identifier.key_info
        )
        shared_secret = pow(
            peer_public,
            int.from_bytes(private_key, "big"),
            field_order,
        ).to_bytes(key_length, "big")
        secret_hash = "sha256"
    else:
        curve_name, _key_length, coord_x, coord_y = _ref_unpack_ecdh_key(
            key_identifier.key_info
        )
        secret_hash = _CURVE_HASH[curve_name]
        peer = ec.EllipticCurvePublicNumbers(coord_x, coord_y, _CURVE[curve_name]).public_key()
        ephemeral = ec.derive_private_key(int.from_bytes(private_key, "big"), _CURVE[curve_name])
        shared_secret = ephemeral.exchange(ec.ECDH(), peer)

    other_info = ALGORITHM_ID_SHA512 + KDS_PUBLIC_KEY_CONTEXT + KDS_LABEL
    secret = _ref_concat_kdf(
        secret_hash,
        shared_secret,
        other_info,
        _HASH_SIZE[secret_hash],
    )
    return _ref_sp800_108(hash_name, secret, KDS_LABEL, KDS_PUBLIC_KEY_CONTEXT, 32)


def _ref_unpack_kdf_hash_name(kdf_parameters: bytes) -> str:
    """Read the hash name out of an MS-GKDI KDF Parameters blob.

    Layout (all little-endian): 8-byte magic, 4-byte UTF-16 name length,
    4-byte reserved padding, then the NUL-terminated UTF-16-LE name.
    """
    assert kdf_parameters[:8] == b"\x00\x00\x00\x00\x01\x00\x00\x00"
    name_length = struct.unpack("<I", kdf_parameters[8:12])[0]
    name_blob = kdf_parameters[16 : 16 + name_length]
    return name_blob[:-2].decode("utf-16-le")


def _load_vector(scenario: str) -> t.Tuple[dict, DPAPINGBlob]:
    data = json.loads(get_test_data(f"{scenario}.json"))
    return data, DPAPINGBlob.unpack(base64.b16decode(data["Data"]))


def _ref_derive_kek(data: dict, dpapi_blob: DPAPINGBlob) -> bytes:
    """Full independent root key -> L1 -> L2 -> KEK chain for a public vector."""
    key_identifier = dpapi_blob.key_identifier
    hash_name = _HASH_NAME[
        _ref_unpack_kdf_hash_name(base64.b16decode(data["KdfParameters"]))
    ]
    target_sd = dpapi_blob.protection_descriptor.get_target_sd()
    root_key = base64.b16decode(data["RootKeyData"])
    root_key_id = key_identifier.root_key_identifier

    l1_seed = _ref_l1_key(hash_name, target_sd, root_key_id, key_identifier.l0, root_key)
    l2_key = _ref_l2_key(
        hash_name,
        root_key_id,
        key_identifier.l0,
        key_identifier.l1,
        key_identifier.l2,
        31,
        l1_seed,
        31,
        b"",
    )
    return _ref_kek(
        hash_name,
        l2_key,
        key_identifier,
        data["SecretAgreementAlgorithm"],
        data["PrivateKeyLength"] // 8,
    )


# ---------------------------------------------------------------------------
# Field-level wire interoperability
# ---------------------------------------------------------------------------


def test_root_guid_mixed_byte_order() -> None:
    root_key_id = uuid.UUID("73294420-917f-416a-9ec3-86082afafb9e")

    # The first 3 GUID fields are byte-swapped (little-endian) while the clock
    # sequence and node keep their big-endian order.
    assert _ref_guid_bytes_le(root_key_id) == WIRE_GUID_MIXED_ENDIAN
    assert root_key_id.bytes == WIRE_GUID_BIG_ENDIAN
    assert _ref_guid_bytes_le(root_key_id) != root_key_id.bytes

    request = GetKey(
        target_sd=b"",
        root_key_id=root_key_id,
        l0_key_id=0,
        l1_key_id=0,
        l2_key_id=0,
    )
    packed = request.pack()

    # The NDR referent header precedes the 16-byte GUID in the packed request.
    referent = b"\x00\x00\x02\x00\x00\x00\x00\x00"
    guid_offset = packed.index(referent) + len(referent)
    assert packed[guid_offset : guid_offset + 16] == WIRE_GUID_MIXED_ENDIAN
    # Round-trip through the parser restores the original Python UUID.
    assert GetKey.unpack(packed).root_key_id == root_key_id


@pytest.mark.parametrize(
    "value, expected",
    [
        (-1, bytes.fromhex("ffffffff")),
        (0, bytes.fromhex("00000000")),
        (31, bytes.fromhex("1f000000")),
        (-2147483648, bytes.fromhex("00000080")),
        (2147483647, bytes.fromhex("ffffff7f")),
    ],
    ids=["negative-one", "zero", "positive", "int32-min", "int32-max"],
)
def test_l0_l1_l2_signed_encoding(value: int, expected: bytes) -> None:
    assert _ref_signed_long(value) == expected
    # A positive value encoded as unsigned would collide with a different
    # signed integer once the high bit is set; guard the boundary explicitly.
    assert struct.unpack("<l", expected)[0] == value

    request = GetKey(
        target_sd=b"",
        root_key_id=None,
        l0_key_id=value,
        l1_key_id=value,
        l2_key_id=value,
    )
    packed = request.pack()
    # With no root key the three LONGs are the final 12 bytes of the stub.
    assert packed[-12:-8] == expected
    assert packed[-8:-4] == expected
    assert packed[-4:] == expected

    parsed = GetKey.unpack(packed)
    assert (parsed.l0_key_id, parsed.l1_key_id, parsed.l2_key_id) == (value, value, value)


def test_utf16_label_terminator() -> None:
    # "KDS service" is 11 code units; the wire form adds one wide NUL (2 bytes)
    # for a total of 24 bytes, ending in 00 00.
    assert _ref_utf16_terminated("KDS service") == WIRE_KDS_LABEL
    assert len(WIRE_KDS_LABEL) == 24
    assert WIRE_KDS_LABEL[-2:] == b"\x00\x00"
    # Dropping the terminator loses exactly the trailing wide NUL.
    assert "KDS service".encode("utf-16-le") == WIRE_KDS_LABEL[:-2]

    envelope = GroupKeyEnvelope(
        version=1,
        flags=0,
        l0=0,
        l1=0,
        l2=0,
        root_key_identifier=uuid.UUID(int=0),
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=b"",
        secret_algorithm="",
        secret_parameters=b"",
        private_key_length=0,
        public_key_length=0,
        domain_name="",
        forest_name="",
        l1_key=b"",
        l2_key=b"",
    )
    packed = envelope.pack()
    # The first variable field is the NUL-terminated UTF-16 KDF algorithm.
    expected_algorithm = _ref_utf16_terminated("SP800_108_CTR_HMAC")
    assert expected_algorithm in packed
    assert packed.count(expected_algorithm) == 1


def test_kdf_context_field_layout() -> None:
    key_guid = uuid.UUID("73294420-917f-416a-9ec3-86082afafb9e")
    expected = (
        WIRE_GUID_MIXED_ENDIAN
        + _ref_signed_long(-1)
        + _ref_signed_long(1)
        + _ref_signed_long(31)
    )
    assert expected == bytes.fromhex(
        "204429737f916a419ec386082afafb9effffffff010000001f000000"
    )
    assert len(expected) == 28

    # Independently built context must equal the code under test output.
    assert _ref_kdf_context(key_guid, -1, 1, 31) == compute_kdf_context(key_guid, -1, 1, 31)
    assert _ref_kdf_context(key_guid, -1, 1, 31) == expected


# ---------------------------------------------------------------------------
# DH / ECDH KDF context construction with synthetic parameters
# ---------------------------------------------------------------------------


SYNTH_ROOT_KEY = bytes(range(64))
SYNTH_ROOT_KEY_ID = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
SYNTH_TARGET_SD = b"\x01\x02\x03\x04SYNTH-SD"
SYNTH_L0, SYNTH_L1, SYNTH_L2 = 361, 5, 9
SYNTH_HASH = "sha256"


def _synth_l2_key() -> bytes:
    l1_seed = _ref_l1_key(SYNTH_HASH, SYNTH_TARGET_SD, SYNTH_ROOT_KEY_ID, SYNTH_L0, SYNTH_ROOT_KEY)
    return _ref_l2_key(
        SYNTH_HASH,
        SYNTH_ROOT_KEY_ID,
        SYNTH_L0,
        SYNTH_L1,
        SYNTH_L2,
        31,
        l1_seed,
        31,
        b"",
    )


def _seed_envelope(secret_algorithm: str, secret_parameters: bytes, priv_len: int, pub_len: int) -> GroupKeyEnvelope:
    l1_seed = _ref_l1_key(SYNTH_HASH, SYNTH_TARGET_SD, SYNTH_ROOT_KEY_ID, SYNTH_L0, SYNTH_ROOT_KEY)
    return GroupKeyEnvelope(
        version=1,
        flags=2,
        l0=SYNTH_L0,
        l1=31,
        l2=31,
        root_key_identifier=SYNTH_ROOT_KEY_ID,
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=KDFParameters("SHA256").pack(),
        secret_algorithm=secret_algorithm,
        secret_parameters=secret_parameters,
        private_key_length=priv_len,
        public_key_length=pub_len,
        domain_name="",
        forest_name="",
        l1_key=l1_seed,
        l2_key=b"",
    )


def test_ecdh_kdf_context_construction() -> None:
    # Deterministic synthetic peer key (fixed scalar, no RNG, fully reproducible).
    peer = ec.derive_private_key(1234567890123456789012345678901234567890, ec.SECP256R1())
    numbers = peer.public_key().public_numbers()
    peer_public_key = ECDHKey("P256", 32, numbers.x, numbers.y).pack()

    # The reference struct reader must recover the exact wire coordinates.
    curve, key_length, ref_x, ref_y = _ref_unpack_ecdh_key(peer_public_key)
    assert (curve, key_length) == ("P256", 32)
    assert (ref_x, ref_y) == (numbers.x, numbers.y)

    l2_key = _synth_l2_key()
    key_identifier = KeyIdentifier(
        1, 1, SYNTH_L0, SYNTH_L1, SYNTH_L2, SYNTH_ROOT_KEY_ID, peer_public_key, "", ""
    )

    # Independently construct the Concat KDF OtherInfo and assert its layout.
    other_info = WIRE_ALGORITHM_ID_SHA512 + WIRE_PUBLIC_KEY_CONTEXT + WIRE_KDS_LABEL
    assert other_info == ALGORITHM_ID_SHA512 + KDS_PUBLIC_KEY_CONTEXT + KDS_LABEL
    assert other_info.startswith(WIRE_ALGORITHM_ID_SHA512)
    assert other_info.endswith(WIRE_KDS_LABEL)

    reference_kek = _ref_kek(SYNTH_HASH, l2_key, key_identifier, "ECDH_P256", 256 // 8)
    envelope = _seed_envelope("ECDH_P256", b"", 256, 256)
    assert envelope.get_kek(key_identifier) == reference_kek
    assert len(reference_kek) == 32


def test_dh_kdf_context_construction() -> None:
    # Reuse the public RFC 5114 2048-bit MODP group but a deterministic peer.
    parameters = FFCDHParameters.unpack(get_test_data("ffc_dh_parameters"))
    peer_scalar = 9876543210987654321
    peer_y = pow(parameters.generator, peer_scalar, parameters.field_order)
    peer_public_key = FFCDHKey(
        parameters.key_length,
        parameters.field_order,
        parameters.generator,
        peer_y,
    ).pack()

    key_length, field_order, generator, public_key = _ref_unpack_ffc_dh_key(peer_public_key)
    assert key_length == parameters.key_length
    assert field_order == parameters.field_order
    assert generator == parameters.generator
    assert public_key == peer_y

    l2_key = _synth_l2_key()
    key_identifier = KeyIdentifier(
        1, 1, SYNTH_L0, SYNTH_L1, SYNTH_L2, SYNTH_ROOT_KEY_ID, peer_public_key, "", ""
    )

    reference_kek = _ref_kek(SYNTH_HASH, l2_key, key_identifier, "DH", 512 // 8)
    envelope = _seed_envelope("DH", parameters.pack(), 512, 2048)
    assert envelope.get_kek(key_identifier) == reference_kek
    assert len(reference_kek) == 32


# ---------------------------------------------------------------------------
# End-to-end KEK -> CEK unwrap against public vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    [
        "kdf_sha256_nonce",
        "kdf_sha256_dh",
        "kdf_sha256_ecdh_p256",
        "kdf_sha256_ecdh_p384",
        "kdf_sha512_nonce",
        "kdf_sha1_dh",
        "kdf_sha384_ecdh_p384",
    ],
)
def test_kek_to_cek_unwrap_public_vectors(scenario: str) -> None:
    data, dpapi_blob = _load_vector(scenario)

    reference_kek = _ref_derive_kek(data, dpapi_blob)
    assert len(reference_kek) == 32

    # Unwrap the CEK with the independently derived KEK and decrypt content.
    cek = aes_key_unwrap(reference_kek, dpapi_blob.enc_cek)
    plaintext = content_decrypt(
        dpapi_blob.enc_content_algorithm,
        dpapi_blob.enc_content_parameters,
        cek,
        dpapi_blob.enc_content,
    )
    assert plaintext == b"\x00"

    # The SUT's own derivation must agree with the independent reference KEK,
    # proving the wire conversions (GUID endianness, signed LONGs, labels and
    # KDF contexts) are interoperable rather than merely self-consistent.
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
    envelope = cache._get_key(
        dpapi_blob.protection_descriptor.get_target_sd(),
        dpapi_blob.key_identifier.root_key_identifier,
        dpapi_blob.key_identifier.l0,
        dpapi_blob.key_identifier.l1,
        dpapi_blob.key_identifier.l2,
    )
    assert envelope is not None
    assert envelope.get_kek(dpapi_blob.key_identifier) == reference_kek


# ---------------------------------------------------------------------------
# Mutation tests: prove the suite localizes the source of an error
# ---------------------------------------------------------------------------


def test_byte_order_mutation_is_detected() -> None:
    data, dpapi_blob = _load_vector("kdf_sha256_nonce")
    key_identifier = dpapi_blob.key_identifier
    key_guid = key_identifier.root_key_identifier
    root_key = base64.b16decode(data["RootKeyData"])
    target_sd = dpapi_blob.protection_descriptor.get_target_sd()

    correct_guid = _ref_guid_bytes_le(key_guid)
    buggy_guid = key_guid.bytes  # RFC big-endian layout, wrong for NDR
    assert correct_guid != buggy_guid

    def full_chain(guid_wire: bytes) -> bytes:
        # Same L1/L2 derivation as the reference but with an injectable GUID
        # wire representation, so only the byte order is mutated.
        l1_seed = _ref_l1_key_with_guid_wire(
            "sha256", target_sd, guid_wire, key_identifier.l0, root_key
        )
        l2_key = _ref_l2_key_with_guid_wire(
            "sha256",
            guid_wire,
            key_identifier.l0,
            key_identifier.l1,
            key_identifier.l2,
            31,
            l1_seed,
            31,
            b"",
        )
        return _ref_sp800_108(
            "sha256",
            l2_key,
            KDS_LABEL,
            key_identifier.key_info,
            32,
        )

    reference_kek = _ref_derive_kek(data, dpapi_blob)

    # The correct mixed-endian GUID reproduces the reference KEK; the big-endian
    # mutation diverges even though every other field is byte-identical.
    assert full_chain(correct_guid) == reference_kek
    buggy_kek = full_chain(buggy_guid)
    assert buggy_kek != reference_kek

    # The wrong KEK fails the AES key-wrap integrity check rather than silently
    # decrypting, so the byte-order error is observable at the CEK boundary.
    with pytest.raises(InvalidUnwrap):
        aes_key_unwrap(buggy_kek, dpapi_blob.enc_cek)


def test_label_terminator_mutation_is_detected() -> None:
    secret = SYNTH_ROOT_KEY
    context = _ref_kdf_context(SYNTH_ROOT_KEY_ID, SYNTH_L0, SYNTH_L1, SYNTH_L2)

    correct_label = _ref_utf16_terminated("KDS service")
    buggy_label = "KDS service".encode("utf-16-le")  # missing wide NUL terminator
    assert correct_label == WIRE_KDS_LABEL
    assert buggy_label == correct_label[:-2]

    correct_output = _ref_sp800_108(SYNTH_HASH, secret, correct_label, context, 32)
    buggy_output = _ref_sp800_108(SYNTH_HASH, secret, buggy_label, context, 32)

    # Same key/context, only the terminator differs: the derived KEK changes.
    assert correct_output != buggy_output
    assert len(buggy_output) == 32

    # A terminator-only defect is distinct from a byte-order defect: the GUID
    # wire bytes are untouched, only the label length shrinks by one wide NUL.
    assert len(correct_label) - len(buggy_label) == 2
    assert buggy_label + b"\x00\x00" == correct_label
