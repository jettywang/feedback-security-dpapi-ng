# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t
import uuid

from ._asn1 import ASN1Reader, ASN1Writer
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

        header_len = 52
        buffer_len = len(view)
        version = int.from_bytes(view[:4], byteorder="little")

        if view[4:8].tobytes() != cls.magic:
            raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")
        if len(view) < header_len:
            raise ValueError(
                f"Failed to unpack {cls.__name__} as the data is shorter than the {header_len} byte header"
            )

        flags = int.from_bytes(view[8:12], byteorder="little")
        l0_index = int.from_bytes(view[12:16], byteorder="little")
        l1_index = int.from_bytes(view[16:20], byteorder="little")
        l2_index = int.from_bytes(view[20:24], byteorder="little")
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        key_info_len = int.from_bytes(view[40:44], byteorder="little")
        domain_len = int.from_bytes(view[44:48], byteorder="little")
        forest_len = int.from_bytes(view[48:52], byteorder="little")
        view = view[header_len:]

        def take_bytes(field: str, length: int, minimum: int = 0) -> memoryview:
            nonlocal view
            offset = buffer_len - len(view)
            if length < minimum:
                raise ValueError(
                    f"Failed to unpack {cls.__name__} as the {field} at offset {offset} has length {length}, "
                    f"smaller than the minimum {minimum}"
                )
            if length > len(view):
                raise ValueError(
                    f"Failed to unpack {cls.__name__} as the {field} at offset {offset} has length {length}, "
                    f"exceeding the {len(view)} remaining bytes"
                )
            chunk = view[:length]
            view = view[length:]
            return chunk

        def take_string(field: str, length: int) -> str:
            field_offset = buffer_len - len(view)
            chunk = take_bytes(field, length, minimum=2)
            body_offset = field_offset
            if chunk[-2:].tobytes() != b"\x00\x00":
                raise ValueError(
                    f"Failed to unpack {cls.__name__} as the {field} at offset {field_offset} "
                    f"is missing its null terminator at offset {field_offset + length - 2}"
                )
            body = chunk[:-2].tobytes()
            terminator = next(
                (index for index in range(0, len(body), 2) if body[index : index + 2] == b"\x00\x00"),
                None,
            )
            if terminator is not None:
                raise ValueError(
                    f"Failed to unpack {cls.__name__} as the {field} at offset {field_offset} "
                    f"contains an embedded null code unit at offset {body_offset + terminator}"
                )
            try:
                return body.decode("utf-16-le")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"Failed to unpack {cls.__name__} as the {field} at offset {field_offset} "
                    f"has invalid UTF-16 at offset {body_offset + exc.start} ({exc.reason})"
                )

        key_info = take_bytes("key_info", key_info_len).tobytes()
        domain = take_string("domain_name", domain_len)
        forest = take_string("forest_name", forest_len)

        if len(view):
            raise ValueError(
                f"Failed to unpack {cls.__name__} as {len(view)} unexpected bytes at offset "
                f"{buffer_len - len(view)} remain after the last field"
            )

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
    """

    key_identifier: KeyIdentifier
    protection_descriptor: ProtectionDescriptor
    enc_cek: bytes
    enc_cek_algorithm: str
    enc_cek_parameters: t.Optional[bytes]
    enc_content: bytes
    enc_content_algorithm: str
    enc_content_parameters: t.Optional[bytes]

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
    ) -> DPAPINGBlob:
        view = memoryview(data)
        header = ASN1Reader(view).peek_header()
        content_info = ContentInfo.unpack(view[: header.tag_length + header.length], header=header)
        remaining_data = view[header.tag_length + header.length :]

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

        # Some DPAPI blobs don't include the content in the PKCS7 payload but
        # just append after the blob.
        enc_content = enveloped_data.encrypted_content_info.content or remaining_data.tobytes()

        return DPAPINGBlob(
            key_identifier=key_identifier,
            protection_descriptor=protection_descriptor,
            enc_cek=kek_info.encrypted_key,
            enc_cek_algorithm=kek_info.key_encryption_algorithm.algorithm,
            enc_cek_parameters=kek_info.key_encryption_algorithm.parameters,
            enc_content=enc_content,
            enc_content_algorithm=enveloped_data.encrypted_content_info.algorithm.algorithm,
            enc_content_parameters=enveloped_data.encrypted_content_info.algorithm.parameters,
        )
