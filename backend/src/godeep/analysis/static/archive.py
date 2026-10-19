"""Bounded ZIP-container triage, not Android signature or manifest verification.

No member is extracted or decompressed. ZIP64 and multipart archives are rejected
for this initial intake profile. Deep parsing belongs in isolated workers.
"""

import stat
import struct
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

from godeep.core.config import Settings


class InvalidAPK(ValueError):
    pass


def validate_archive(path: Path, settings: Settings) -> None:
    size = path.stat().st_size
    with path.open("rb") as source:
        source.seek(max(0, size - 65557))
        tail = source.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise InvalidAPK("Missing ZIP end-of-directory record")
    if position >= 20 and tail[position - 20 : position - 16] == b"PK\x06\x07":
        raise InvalidAPK("ZIP64 archives are not supported by this intake profile")
    fields = struct.unpack_from("<4s4H2LH", tail, position)
    _, disk, start_disk, disk_entries, entries, cd_size, cd_offset, comment_size = fields
    if disk or start_disk or disk_entries != entries:
        raise InvalidAPK("Multipart archives are not supported")
    if entries == 65535 or cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        raise InvalidAPK("ZIP64 archives are not supported by this intake profile")
    if entries > settings.max_archive_entries or cd_size > settings.max_central_directory_bytes:
        raise InvalidAPK("Archive directory exceeds configured limits")
    eocd_offset = size - len(tail) + position
    if position + 22 + comment_size != len(tail) or cd_offset + cd_size > eocd_offset:
        raise InvalidAPK("Invalid archive directory bounds")
    try:
        with ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) != entries:
                raise InvalidAPK("Inconsistent archive entry count")
            names = set()
            total = 0
            manifest = None
            for member in members:
                name = member.filename
                parts = PurePosixPath(name).parts
                if (
                    not name
                    or name.startswith("/")
                    or "\\" in name
                    or ":" in name
                    or ".." in parts
                    or "\x00" in member.orig_filename
                ):
                    raise InvalidAPK("Unsafe archive member name")
                if name in names:
                    raise InvalidAPK("Duplicate archive member name")
                names.add(name)
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise InvalidAPK("Symbolic link members are not accepted")
                if member.flag_bits & 1:
                    raise InvalidAPK("Encrypted ZIP members are not accepted")
                if member.header_offset < 0 or member.header_offset + 30 > cd_offset:
                    raise InvalidAPK("Invalid member location")
                total += member.file_size
                if total > settings.max_uncompressed_bytes:
                    raise InvalidAPK("Declared archive expansion exceeds configured limit")
                if name == "AndroidManifest.xml":
                    manifest = member
            if manifest is None or manifest.is_dir() or manifest.file_size == 0:
                raise InvalidAPK("A nonempty root AndroidManifest.xml is required")
    except (BadZipFile, NotImplementedError, struct.error, UnicodeError) as exc:
        raise InvalidAPK("Malformed ZIP archive") from exc
