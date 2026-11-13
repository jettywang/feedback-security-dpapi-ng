# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
import uuid

from ._asn1 import ASN1Reader, ASN1Writer, NotEnougData
from ._pkcs7 import (
    AlgorithmIdentifier,
    ContentInfo,
    EncryptedContentInfo,
    EnvelopedData,
    KEKIdentifier,
    KEKRecipientInfo,
    OtherKeyAttribute,
)
from ._security_descriptor import ace_to_bytes, sd_to_bytes


class BlobParseStrategy(enum.Enum):
    """Strategy used to locate the encrypted content in a DPAPI-NG blob.

    The encrypted content of a DPAPI-NG blob can either be embedded in the
    CMS EnvelopedData structure (the general ``NCryptProtectSecret`` form) or
    appended after the ASN.1 envelope (the LAPS style). This controls how
    :meth:`DPAPINGBlob.unpack` selects which bytes are the authoritative
    encrypted content.

    Args:
        AUTO: Use the only location that contains data but fail if both
            locations (or neither) contain data, or if a second complete CMS
            envelope is present.
        EMBEDDED: Only use the ``encryptedContent`` inside the EnvelopedData.
            Any trailing data, including an empty embedded content, is a
            failure.
        APPENDED: Only use the bytes appended after the ASN.1 envelope. The
            EnvelopedData must not contain an embedded ``encryptedContent``
            and there must be trailing data.
    """

    AUTO = "auto"
    EMBEDDED = "embedded"
    APPENDED = "appended"


class EncryptedContentSource(enum.Enum):
    """The location the encrypted content was read from.

    This is recorded on the unpacked :class:`DPAPINGBlob` so callers know
    which bytes were actually decrypted. Any bytes that were ignored during
    parsing are not authenticated and must never be treated as the protected
    content.

    Args:
        EMBEDDED: The encrypted content came from the EnvelopedData
            ``encryptedContent`` field.
        APPENDED: The encrypted content came from the bytes appended after
            the ASN.1 envelope (LAPS style).
    """

    EMBEDDED = "embedded"
    APPENDED = "appended"


def _is_complete_envelope(data: t.Union[bytes, bytearray, memoryview]) -> bool:
    # Check whether the data is a whole CMS ContentInfo wrapping an
    # EnvelopedData, i.e. a second full DPAPI-NG style envelope. Raw LAPS
    # ciphertext is an AES-GCM value without ASN.1 framing so it never parses
    # as one. A complete second envelope means there are two authoritative
    # structures and the caller must not guess which one to use.
    view = memoryview(data)
    if not view:
        return False

    try:
        header = ASN1Reader(view).peek_header()
        envelope_end = header.tag_length + header.length
        if len(view) < envelope_end:
            return False

        content_info = ContentInfo.unpack(view[:envelope_end], header=header)
    except (NotEnougData, ValueError):
        return False

    return content_info.content_type == EnvelopedData.CONTENT_TYPE_ENVELOPED_DATA_OID


@dataclasses.dataclass(frozen=True)
class KeyIdentifier:
    """Key Identifier.

    This contains the key identifier info that can be used by MS-GKDI GetKey
    to retrieve the group key seed values. This structure is not defined
    publicly by Microsoft but it closely matches the :class:`GroupKeyEnvelope`
    structure.

    Args:
        version: The version of the structure, should be 1
        flags: Flags describing the values inside the structure
        l0: The L0 index of the key
        l1: The L1 index of the key
        l2: The L2 index of the key
        root_key_identifier: The key identifier
        key_info: If is_public_key this is the public key, else it is the key
            KDF context value.
        domain_name: The domain name of the server in DNS format.
        forest_name: The forest name of the server in DNS format.
    """

    version: int
    magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x4B\x44\x53\x4B")
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    key_info: bytes
    domain_name: str
    forest_name: str

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    def pack(self) -> bytes:
        b_domain_name = (self.domain_name + "\00").encode("utf-16-le")
        b_forest_name = (self.forest_name + "\00").encode("utf-16-le")

        return b"".join(
            [
                self.version.to_bytes(4, byteorder="little"),
                self.magic,
                self.flags.to_bytes(4, byteorder="little"),
                self.l0.to_bytes(4, byteorder="little"),
                self.l1.to_bytes(4, byteorder="little"),
                self.l2.to_bytes(4, byteorder="little"),
                self.root_key_identifier.bytes_le,
                len(self.key_info).to_bytes(4, byteorder="little"),
                len(b_domain_name).to_bytes(4, byteorder="little"),
                len(b_forest_name).to_bytes(4, byteorder="little"),
                self.key_info,
                b_domain_name,
                b_forest_name,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> KeyIdentifier:
        view = memoryview(data)

        version = int.from_bytes(view[:4], byteorder="little")

        if view[4:8].tobytes() != cls.magic:
            raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

        flags = int.from_bytes(view[8:12], byteorder="little")
        l0_index = int.from_bytes(view[12:16], byteorder="little")
        l1_index = int.from_bytes(view[16:20], byteorder="little")
        l2_index = int.from_bytes(view[20:24], byteorder="little")
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        key_info_len = int.from_bytes(view[40:44], byteorder="little")
        domain_len = int.from_bytes(view[44:48], byteorder="little")
        forest_len = int.from_bytes(view[48:52], byteorder="little")
        view = view[52:]

        key_info = view[:key_info_len].tobytes()
        view = view[key_info_len:]

        # Take away 2 for the final null padding
        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        return KeyIdentifier(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            key_info=key_info,
            domain_name=domain,
            forest_name=forest,
        )


class ProtectionDescriptorType(enum.Enum):
    SID = "1.3.6.1.4.1.311.74.1.1"
    KEY_FILE = "1.3.6.1.4.1.311.74.1.2"  # KeyFile in UF8String type
    SDDL = "1.3.6.1.4.1.311.74.1.5"
    LOCAL = "1.3.6.1.4.1.311.74.1.8"


@dataclasses.dataclass(frozen=True)
class ProtectionDescriptor:
    type: ProtectionDescriptorType
    value: str

    def get_target_sd(self) -> bytes:
        raise NotImplementedError()  # pragma: nocover

    def pack(self) -> bytes:
        writer = ASN1Writer()

        with writer.push_sequence() as w:
            w.write_object_identifier(self.type.value)

            with w.push_sequence() as w1:
                with w1.push_sequence() as w2:
                    with w2.push_sequence() as w3:
                        w3.write_utf8_string(self.type.name)
                        w3.write_utf8_string(self.value)

        return writer.get_data()

    @classmethod
    def parse(
        cls,
        value: str,
    ) -> ProtectionDescriptor:
        # Currently only the SID type is supported
        return SIDDescriptor(value)

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> ProtectionDescriptor:
        reader = ASN1Reader(data).read_sequence()
        content_type = reader.read_object_identifier()

        reader = reader.read_sequence().read_sequence().read_sequence()
        value_type = reader.read_utf8_string()
        value = reader.read_utf8_string()

        if content_type == ProtectionDescriptorType.SID.value and value_type == "SID":
            return SIDDescriptor(value)

        else:
            raise ValueError(f"DPAPI-NG protection descriptor type {content_type} '{value_type}' is unsupported")


@dataclasses.dataclass(frozen=True)
class SIDDescriptor(ProtectionDescriptor):
    type: ProtectionDescriptorType = dataclasses.field(init=False, default=ProtectionDescriptorType.SID)

    def get_target_sd(self) -> bytes:
        # Build the target security descriptor from the SID passed in. This SD
        # contains an ACE per target user with a mask of 0x3 and a final ACE of
        # the current user with a mask of 0x2. When viewing this over the wire
        # the current user is set as S-1-1-0 (World) and the owner/group is
        # S-1-5-18 (SYSTEM).
        return sd_to_bytes(
            owner="S-1-5-18",
            group="S-1-5-18",
            dacl=[ace_to_bytes(self.value, 3), ace_to_bytes("S-1-1-0", 2)],
        )


@dataclasses.dataclass
class DPAPINGBlob:
    MICROSOFT_SOFTWARE_OID = "1.3.6.1.4.1.311.74.1"

    """DPAPI NG Blob.

    The unpacked DPAPI NG blob that contains the information needed to decrypt
    the encrypted content. The key identifier and protection descriptor can be
    used to generate the KEK. The KEK is used to decrypt the encrypted CEK. The
    CEK can be used to decrypt the encrypted contents.

    Args:
        key_identifier: The key identifier for the KEK.
        protection_descriptor: The protection descriptor that protects the key.
        enc_cek: The encrypted CEK.
        enc_cek_algorithm: The encrypted CEK algorithm OID.
        enc_cek_parameters: The encrypted CEK algorithm parameters.
        enc_content: The encrypted content.
        enc_content_algorithm: The encrypted content algorithm OID.
        enc_content_parameters: The encrypted content parameters.
        enc_content_source: Where the encrypted content was read from when the
            blob was unpacked. Ignored bytes are never selected so they cannot
            be mistaken for authenticated protected content.
    """

    key_identifier: KeyIdentifier
    protection_descriptor: ProtectionDescriptor
    enc_cek: bytes
    enc_cek_algorithm: str
    enc_cek_parameters: t.Optional[bytes]
    enc_content: bytes
    enc_content_algorithm: str
    enc_content_parameters: t.Optional[bytes]
    enc_content_source: EncryptedContentSource = EncryptedContentSource.EMBEDDED

    def pack(
        self,
        blob_in_envelope: bool = True,
    ) -> bytes:
        """Pack the DPAPI-NG Blob

        Packs the DPAPI-NG blob into a byte string.

        Args:
            blob_in_envelope: True to store the encrypted blob in the
                EnvelopedData structure (NCryptProtectSecret general), False to
                append the encrypted blob after the EnvelopedData structure
                (LAPS style).

        Returns:
            bytes: The DPAPI NG Blob data.
        """
        writer = ASN1Writer()

        recipient_info = KEKRecipientInfo(
            version=4,
            kekid=KEKIdentifier(
                key_identifier=self.key_identifier.pack(),
                other=OtherKeyAttribute(
                    key_attr_id=DPAPINGBlob.MICROSOFT_SOFTWARE_OID,
                    key_attr=self.protection_descriptor.pack(),
                ),
            ),
            key_encryption_algorithm=AlgorithmIdentifier(
                self.enc_cek_algorithm,
                self.enc_cek_parameters,
            ),
            encrypted_key=self.enc_cek,
        )

        enveloped_data = EnvelopedData(
            version=2,
            recipient_infos=[recipient_info],
            encrypted_content_info=EncryptedContentInfo(
                content_type=EnvelopedData.CONTENT_TYPE_DATA_OID,
                algorithm=AlgorithmIdentifier(
                    algorithm=self.enc_content_algorithm,
                    parameters=self.enc_content_parameters,
                ),
                content=self.enc_content if blob_in_envelope else b"",
            ),
        )
        writer = ASN1Writer()
        enveloped_data.pack(writer)

        content_info = ContentInfo(
            content_type=EnvelopedData.CONTENT_TYPE_ENVELOPED_DATA_OID,
            content=writer.get_data(),
        )
        writer = ASN1Writer()
        content_info.pack(writer)

        return b"".join(
            [
                writer.get_data(),
                b"" if blob_in_envelope else self.enc_content,
            ]
        )

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
        strategy: BlobParseStrategy = BlobParseStrategy.AUTO,
    ) -> DPAPINGBlob:
        """Unpack the DPAPI-NG Blob.

        The encrypted content can either be embedded in the CMS
        EnvelopedData structure (the general ``NCryptProtectSecret`` form) or
        appended after the ASN.1 envelope (the LAPS style). The ``strategy``
        controls which location is treated as authoritative so ambiguous
        blobs are rejected instead of silently choosing one set of bytes.

        Args:
            data: The raw DPAPI-NG blob bytes.
            strategy: The :class:`BlobParseStrategy` used to locate the
                encrypted content. Defaults to :attr:`BlobParseStrategy.AUTO`
                which accepts the single valid form but rejects blobs where
                both, or neither, location carries content.

        Returns:
            DPAPINGBlob: The unpacked blob. The ``enc_content_source`` field
            records which bytes were selected; any bytes that were not
            selected are never authenticated and cannot be mistaken for the
            protected content.
        """
        if not isinstance(strategy, BlobParseStrategy):
            raise ValueError(
                f"DPAPI-NG parse strategy must be a BlobParseStrategy value but got {type(strategy).__name__}"
            )

        view = memoryview(data)
        try:
            header = ASN1Reader(view).peek_header()
        except NotEnougData as e:
            raise ValueError("DPAPI-NG blob is truncated and does not contain a valid ASN.1 header") from e

        envelope_end = header.tag_length + header.length
        if len(view) < envelope_end:
            raise ValueError(
                f"DPAPI-NG blob is truncated: ASN.1 envelope declares {header.length} bytes "
                f"but only {len(view) - header.tag_length} are available"
            )

        content_info = ContentInfo.unpack(view[:envelope_end], header=header)
        remaining_data = view[envelope_end:].tobytes()

        if content_info.content_type != EnvelopedData.CONTENT_TYPE_ENVELOPED_DATA_OID:
            raise ValueError(f"DPAPI-NG blob content type '{content_info.content_type}' is unsupported")
        enveloped_data = EnvelopedData.unpack(content_info.content)

        if (
            enveloped_data.version != 2
            or len(enveloped_data.recipient_infos) != 1
            or not isinstance(enveloped_data.recipient_infos[0], KEKRecipientInfo)
            or enveloped_data.recipient_infos[0].version != 4
        ):
            raise ValueError(f"DPAPI-NG blob is not in the expected format")

        kek_info = enveloped_data.recipient_infos[0]
        key_identifier = KeyIdentifier.unpack(kek_info.kekid.key_identifier)

        if not kek_info.kekid.other or kek_info.kekid.other.key_attr_id != DPAPINGBlob.MICROSOFT_SOFTWARE_OID:
            raise ValueError("DPAPI-NG KEK Id is not in the expected format")

        protection_descriptor = ProtectionDescriptor.unpack(kek_info.kekid.other.key_attr or b"")

        # The encrypted content is either embedded in the PKCS7 payload or
        # appended after the envelope (LAPS style). Resolve which bytes are
        # authoritative according to the requested strategy rather than
        # silently preferring one location when both are present.
        embedded_content = enveloped_data.encrypted_content_info.content
        has_embedded = bool(embedded_content)
        has_appended = bool(remaining_data)
        second_envelope = _is_complete_envelope(remaining_data)

        enc_content: bytes
        enc_content_source: EncryptedContentSource

        if second_envelope:
            raise ValueError(
                "DPAPI-NG blob contains a second complete CMS EnvelopedData after the first "
                "envelope and it is ambiguous which one is authoritative"
            )

        if strategy == BlobParseStrategy.EMBEDDED:
            if not has_embedded:
                raise ValueError(
                    "DPAPI-NG blob parse strategy 'embedded' requires encryptedContent in the "
                    "EnvelopedData but none was present"
                )
            if has_appended:
                raise ValueError(
                    "DPAPI-NG blob parse strategy 'embedded' found unexpected trailing data after "
                    "the ASN.1 envelope"
                )
            enc_content = t.cast(bytes, embedded_content)
            enc_content_source = EncryptedContentSource.EMBEDDED

        elif strategy == BlobParseStrategy.APPENDED:
            if has_embedded:
                raise ValueError(
                    "DPAPI-NG blob parse strategy 'appended' found encryptedContent embedded in the "
                    "EnvelopedData as well as trailing data"
                )
            if not has_appended:
                raise ValueError(
                    "DPAPI-NG blob parse strategy 'appended' requires encrypted content appended "
                    "after the ASN.1 envelope but none was present"
                )
            enc_content = remaining_data
            enc_content_source = EncryptedContentSource.APPENDED

        else:
            if has_embedded and has_appended:
                raise ValueError(
                    "DPAPI-NG blob contains encrypted content both in the EnvelopedData and appended "
                    "after the ASN.1 envelope and it is ambiguous which one is authoritative"
                )
            if not has_embedded and not has_appended:
                raise ValueError(
                    "DPAPI-NG blob contains no encrypted content in either the EnvelopedData or "
                    "after the ASN.1 envelope"
                )

            if has_embedded:
                enc_content = t.cast(bytes, embedded_content)
                enc_content_source = EncryptedContentSource.EMBEDDED
            else:
                enc_content = remaining_data
                enc_content_source = EncryptedContentSource.APPENDED

        return DPAPINGBlob(
            key_identifier=key_identifier,
            protection_descriptor=protection_descriptor,
            enc_cek=kek_info.encrypted_key,
            enc_cek_algorithm=kek_info.key_encryption_algorithm.algorithm,
            enc_cek_parameters=kek_info.key_encryption_algorithm.parameters,
            enc_content=enc_content,
            enc_content_algorithm=enveloped_data.encrypted_content_info.algorithm.algorithm,
            enc_content_parameters=enveloped_data.encrypted_content_info.algorithm.parameters,
            enc_content_source=enc_content_source,
        )
