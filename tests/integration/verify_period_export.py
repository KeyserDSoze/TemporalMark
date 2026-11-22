#!/usr/bin/env python3
"""Offline v1 period ZIP *internal* consistency only. Never a QTSP verifier.

Usage: python3 tests/integration/verify_period_export.py path/to/export.zip
No network, no extraction, no secret/log/DER output. See ADR 0076, #107.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import stat
import struct
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

FORMAT = "temporalmark-period-export-v1"
MAX_COUNT = 10_000
MAX_DER = 1_048_576
MAX_TOTAL_DER = 67_108_864
MAX_MANIFEST = 8 * 1024 * 1024
MAX_ARCHIVE = 80 * 1024 * 1024
SHA256_OID = "2.16.840.1.101.3.4.2.1"
HEX_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
UTC_TIME = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(?:Z|\+00:00)\Z"
)
MANIFEST_KEYS = {
    "format", "organizationId", "fromUtc", "toUtcExclusive",
    "exportedAtUtc", "count", "entries"
}
ENTRY_KEYS = {
    "Id", "IssuedUtc", "HashAlgorithmOid", "DigestBase64",
    "PolicyOid", "ProviderId", "TokenSha256Hex", "validationState",
    "EvidenceReference", "responseFile"
}


class ExportVerificationError(ValueError):
    """Generic failure. Never echo untrusted names, DER or manifest values."""


def require(condition: bool) -> None:
    if not condition:
        raise ExportVerificationError("Period ZIP local consistency check failed.")


def parse_utc_ticks(value: object) -> int:
    """Parse an explicit UTC .NET DateTimeOffset with exact 100ns precision."""
    require(isinstance(value, str))
    match = UTC_TIME.fullmatch(value)
    require(match is not None)
    try:
        whole = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ExportVerificationError("Invalid UTC timestamp.") from None
    delta = whole.replace(tzinfo=timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    seconds = delta.days * 86_400 + delta.seconds
    fraction = int((match.group(2) or "").ljust(7, "0"))
    return seconds * 10_000_000 + fraction


def parse_uuid(value: object) -> uuid.UUID:
    require(isinstance(value, str))
    try:
        result = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise ExportVerificationError("Invalid record identity.") from None
    # No UUID aliases, braces, uppercase or hyphenless spellings in v1.
    require(str(result) == value)
    require(result.int != 0)
    return result


def parse_digest(value: object) -> None:
    require(isinstance(value, str) and len(value) == 44)
    try:
        digest = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ExportVerificationError("Invalid imprint encoding.") from None
    require(len(digest) == 32 and base64.b64encode(digest).decode("ascii") == value)


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    unique = {}
    for key, value in pairs:
        require(key not in unique)
        unique[key] = value
    return unique


def reject_json_constant(value: str) -> None:
    raise ExportVerificationError("Unsupported JSON constant.")


def read_bounded(zipped: zipfile.ZipFile, info: zipfile.ZipInfo,
                 limit: int) -> bytes:
    require(info.file_size <= limit)
    # Even if a malicious directory header lies about uncompressed size,
    # never expand more than limit+1 bytes from an individual ZIP member.
    with zipped.open(info, "r") as member:
        data = member.read(limit + 1)
    require(len(data) <= limit and len(data) == info.file_size)
    return data


def require_local_central_metadata_match(
        zipped: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    """Check two ZIP views before any member is decompressed (ADR 0078).

    Python ZipFile.open() binds local filename to central filename but does
    not compare local compression/flags to the central ZipInfo. Deliberately
    read only a 30-byte fixed header; never extract member paths.
    """
    offset = info.header_offset
    require(isinstance(offset, int) and 0 <= offset <= MAX_ARCHIVE - 30)
    require(zipped.fp is not None)
    zipped.fp.seek(offset)
    header = zipped.fp.read(30)
    require(len(header) == 30 and header[:4] == b"PK\x03\x04")
    local_flags, local_method = struct.unpack_from("<HH", header, 6)
    require(local_flags == info.flag_bits and
            local_method == info.compress_type)


def archive_bytes(source: object) -> int:
    if isinstance(source, (str, Path)):
        return Path(source).stat().st_size
    position = source.tell()
    source.seek(0, 2)
    end = source.tell()
    source.seek(position)
    return end


def require_exact_v1_zip_envelope(
        zipped: zipfile.ZipFile, archive_size: int, member_count: int) -> None:
    """Reject prefix/trailer/ZIP64/multi-disk ambiguity in *v1* (ADR 0120).

    Generic Python zipfile intentionally accepts ZIP appended to other bytes.
    The current .NET memory-backed v1 producer writes a single ordinary ZIP
    with its first local member at byte zero and a final zero-comment
    22-byte classic EOCD. Inspect ONLY 4+22 fixed bytes before decompression.
    This is NOT a ZIP signature or complete-period custody proof.
    """
    require(archive_size >= 4 + 30 + 46 + 22 and
            1 <= member_count <= MAX_COUNT + 1)
    require(zipped.fp is not None)
    zipped.fp.seek(0)
    require(zipped.fp.read(4) == b"PK\x03\x04")

    # An EOCD with any trailing overlay cannot occupy the final 22 bytes.
    # The v1 format has no ZIP comments or ZIP64/multi-disk footer.
    zipped.fp.seek(archive_size - 22)
    footer = zipped.fp.read(22)
    require(len(footer) == 22)
    (signature, this_disk, central_disk, entries_this_disk, entries_total,
     central_size, central_offset, comment_size) = struct.unpack(
         "<4s4H2LH", footer)
    require(signature == b"PK\x05\x06")
    require(this_disk == 0 and central_disk == 0)
    require(entries_this_disk == entries_total == member_count)
    require(comment_size == 0)
    require(central_offset >= 30 and central_size >= 46 * member_count)
    # No unclaimed gap, hidden attachment, shifted central directory or
    # self-extracting prefix may exist in this intentionally narrow profile.
    require(central_offset + central_size == archive_size - 22)


def verify_archive(source: object) -> int:
    """Return count if a current v1 ZIP is locally self-consistent only."""
    try:
        size = archive_bytes(source)
        require(size <= MAX_ARCHIVE)
        with zipfile.ZipFile(source, "r") as zipped:
            infos = zipped.infolist()
            # Check the full physical v1 container before reading any
            # manifest JSON or TSR; zipfile alone tolerates ZIP overlays.
            require_exact_v1_zip_envelope(zipped, size, len(infos))
            require(1 <= len(infos) <= MAX_COUNT + 1)
            names = [item.filename for item in infos]
            require(len(names) == len(set(names)))
            require("manifest.json" in names)
            require(not zipped.comment)
            for info in infos:
                require_local_central_metadata_match(zipped, info)
                require(not info.is_dir())
                require(not (info.flag_bits & 0x1))  # no encrypted members
                # Current .NET v1 exports regular files using STORE/DEFLATE.
                # Reject unfamiliar compressors *before* decompression, even
                # when Python supports them (BZIP2/LZMA), and never extract.
                require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
                if info.create_system == 3:  # Unix external file-type bits
                    file_type = stat.S_IFMT(info.external_attr >> 16)
                    # 0 = producer omitted Unix type; any other special
                    # file (FIFO/device/socket/dir/symlink) is never a TSR.
                    require(file_type in (0, stat.S_IFREG))
                # An exact member allowlist is applied after parsing the
                # bounded manifest. Never extract files to a filesystem.
                require(info.filename == "manifest.json" or
                        re.fullmatch(r"tokens/[0-9a-f]{32}\.tsr", info.filename) is not None)

            manifest_info = zipped.getinfo("manifest.json")
            raw = read_bounded(zipped, manifest_info, MAX_MANIFEST)
            info = json.loads(
                raw.decode("utf-8"), object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_json_constant)
            require(isinstance(info, dict) and set(info) == MANIFEST_KEYS)
            require(info["format"] == FORMAT)
            parse_uuid(info["organizationId"])
            start, end = parse_utc_ticks(info["fromUtc"]), parse_utc_ticks(info["toUtcExclusive"])
            require(start < end)
            parse_utc_ticks(info["exportedAtUtc"])
            rows = info["entries"]
            count = info["count"]
            require(isinstance(count, int) and not isinstance(count, bool))
            require(isinstance(rows, list) and len(rows) == count and 0 <= count <= MAX_COUNT)
            require(len(infos) == count + 1)

            expected = {"manifest.json"}
            seen_ids: set[str] = set()
            total = 0
            for row in rows:
                require(isinstance(row, dict) and set(row) == ENTRY_KEYS)
                rid = parse_uuid(row["Id"])
                require(str(rid) not in seen_ids)
                seen_ids.add(str(rid))
                require(row["responseFile"] == f"tokens/{rid.hex}.tsr")
                require(row["responseFile"] in names)
                expected.add(row["responseFile"])
                issued = parse_utc_ticks(row["IssuedUtc"])
                require(start <= issued < end)
                require(row["HashAlgorithmOid"] == SHA256_OID)
                parse_digest(row["DigestBase64"])
                require(isinstance(row["PolicyOid"], str) and bool(row["PolicyOid"].strip()))
                require(isinstance(row["ProviderId"], str) and bool(row["ProviderId"].strip()))
                # The only state the current delegated pilot may issue.
                # A manifest alone cannot establish any higher trust.
                require(row["validationState"] == "Unverified")
                require(row["EvidenceReference"] is None or
                        isinstance(row["EvidenceReference"], str))
                expected_hash = row["TokenSha256Hex"]
                require(isinstance(expected_hash, str) and HEX_SHA256.fullmatch(expected_hash) is not None)
                member_info = zipped.getinfo(row["responseFile"])
                size = member_info.file_size
                require(0 < size <= MAX_DER and size <= MAX_TOTAL_DER - total)
                total += size
                token = read_bounded(zipped, member_info, MAX_DER)
                require(hashlib.sha256(token).hexdigest() == expected_hash.lower())

            require(set(names) == expected)
            return count
    except ExportVerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError,
            EOFError, UnicodeError, zipfile.BadZipFile, OverflowError):
        raise ExportVerificationError("Period ZIP local consistency check failed.") from None


def main(args: list[str]) -> int:
    if len(args) != 1:
        print("Usage: verify_period_export.py <export.zip>", file=sys.stderr)
        return 2
    try:
        count = verify_archive(Path(args[0]))
    except ExportVerificationError:
        print("Period ZIP local consistency check FAILED; no trust assertion.", file=sys.stderr)
        return 1
    print(f"LOCAL ZIP STRUCTURE/SHA256 CONSISTENT: {count} receipts. "
          "NOT signed, qualified, complete-period proof or RFC3161 signature validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
