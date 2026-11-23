"""RED-first #107: offline ZIP structural and hash checks, NOT QTSP trust."""
import base64
import contextlib
import hashlib
import io
import json
import stat
import struct
import tempfile
import sys
import unittest
import warnings
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_period_export as verifier

ORG = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RID = "11111111-1111-4111-8111-111111111111"
START = "2026-11-01T00:00:00+00:00"
END = "2026-12-01T00:00:00+00:00"
DER = b"\x30\x02\x01\x00"


def record(der=DER, rid=RID, **changes):
    result = {
        "Id": rid,
        "IssuedUtc": "2026-11-15T09:00:00.1234567+00:00",
        "HashAlgorithmOid": "2.16.840.1.101.3.4.2.1",
        "DigestBase64": base64.b64encode(b"\x00" * 32).decode("ascii"),
        "PolicyOid": "1.2.3.4",
        "ProviderId": "test-pilot-only",
        "TokenSha256Hex": hashlib.sha256(der).hexdigest().upper(),
        "validationState": "Unverified",
        "EvidenceReference": None,
        "responseFile": f"tokens/{rid.replace('-', '')}.tsr",
    }
    result.update(changes)
    return result


def manifest(entries=None, **changes):
    result = {
        "format": "temporalmark-period-export-v1",
        "organizationId": ORG,
        "fromUtc": START,
        "toUtcExclusive": END,
        "exportedAtUtc": "2026-11-18T10:00:00+00:00",
        "count": len(entries) if entries is not None else 1,
        "entries": entries if entries is not None else [record()],
    }
    result.update(changes)
    return result


def build_zip(m=None, files=None, raw_manifest=None, extras=None):
    m = manifest() if m is None else m
    if files is None:
        files = [(row["responseFile"], DER) for row in m["entries"]]
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "manifest.json", raw_manifest if raw_manifest is not None
                else json.dumps(m, separators=(",", ":")).encode("utf-8"))
            for name, data in files:
                archive.writestr(name, data)
            for info, data in (extras or []):
                archive.writestr(info, data)
    return stream.getvalue()


def check(raw):
    return verifier.verify_archive(io.BytesIO(raw))


class OfflinePeriodExportTests(unittest.TestCase):
    def test_cli_proves_only_local_consistency_without_leaking_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-export.zip"
            output = io.StringIO()
            errors = io.StringIO()
            path.write_bytes(build_zip())
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                exit_code = verifier.main([str(path)])
            self.assertEqual(0, exit_code)
            self.assertIn("NOT signed, qualified", output.getvalue())
            self.assertIn("1 receipts", output.getvalue())
            self.assertNotIn(ORG, output.getvalue())
            self.assertEqual("", errors.getvalue())

            # Corrupt the DER while retaining the original stored hash.
            path.write_bytes(build_zip(files=[
                (record()["responseFile"], b"\x30\x02\x01\x01")]))
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                exit_code = verifier.main([str(path)])
            self.assertEqual(1, exit_code)
            self.assertEqual("", output.getvalue())
            self.assertIn("FAILED", errors.getvalue())
            self.assertNotIn(ORG, errors.getvalue())
            self.assertNotIn(str(path), errors.getvalue())

    def test_current_v1_archive_passes_only_local_consistency(self):
        self.assertEqual(1, check(build_zip()))

    # #155 / ADR 0120: Python zipfile may accept a normal v1 ZIP with
    # unreferenced self-extracting-style bytes or opaque trailing material.
    # The offline verifier must be stricter than a generic ZIP reader.
    @staticmethod
    def _assert_python_zip_can_read_original_v1_members(raw):
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            parsed = json.loads(archive.read("manifest.json"))
            assert parsed["format"] == "temporalmark-period-export-v1"
            assert archive.read(record()["responseFile"]) == DER
            assert archive.comment == b""

    def test_non_zip_prefix_polyglot_is_denied_despite_intact_members(self):
        base = build_zip()
        self.assertEqual(1, check(base))
        overlaid = b"POLYGLOT-OPAQUE-PREFIX:" + base
        self._assert_python_zip_can_read_original_v1_members(overlaid)
        with self.assertRaises(verifier.ExportVerificationError):
            check(overlaid)

    def test_appended_non_zip_payload_is_denied_despite_intact_members(self):
        base = build_zip()
        self.assertEqual(1, check(base))
        overlaid = base + b"TRAILER:unreferenced-private-payload"
        self._assert_python_zip_can_read_original_v1_members(overlaid)
        with self.assertRaises(verifier.ExportVerificationError):
            check(overlaid)

    def test_appended_nul_padding_is_denied_despite_intact_members(self):
        base = build_zip()
        self.assertEqual(1, check(base))
        overlaid = base + b"\x00" * 1024
        self._assert_python_zip_can_read_original_v1_members(overlaid)
        with self.assertRaises(verifier.ExportVerificationError):
            check(overlaid)

    def test_simultaneous_prefix_and_suffix_are_denied(self):
        base = build_zip()
        self.assertEqual(1, check(base))
        overlaid = b"HTML-PREFIX-EXTRA" + base + b"PRIVATE-TRAILER"
        self._assert_python_zip_can_read_original_v1_members(overlaid)
        with self.assertRaises(verifier.ExportVerificationError):
            check(overlaid)

    def test_opaque_zip_suffix_cli_failure_is_generic_with_no_private_values(self):
        overlaid = build_zip() + b"OPERATOR-PRIVATE-APPENDED-OVERLAY"
        self._assert_python_zip_can_read_original_v1_members(overlaid)
        with tempfile.TemporaryDirectory() as folder:
            private_path = Path(folder) / "private-tenant-export.zip"
            private_path.write_bytes(overlaid)
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                result = verifier.main([str(private_path)])
            self.assertEqual(1, result)
            self.assertEqual("", output.getvalue())
            self.assertIn("FAILED", errors.getvalue())
            self.assertNotIn(str(private_path), errors.getvalue())
            self.assertNotIn(ORG, errors.getvalue())
            self.assertNotIn("OPERATOR-PRIVATE", errors.getvalue())

    def test_exact_v1_archive_with_zero_or_one_receipt_is_still_accepted(self):
        self.assertEqual(1, check(build_zip()))
        self.assertEqual(0, check(build_zip(manifest([]))))

    def test_empty_period_export_is_allowed(self):
        self.assertEqual(0, check(build_zip(manifest([]))))

    def test_changed_der_with_unchanged_manifest_hash_is_rejected(self):
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(files=[(record()["responseFile"], b"\x30\x02\x01\x01")]))

    def test_empty_der_member_is_denied_even_if_hash_matches(self):
        # TimestampRecord.Validate() refuses empty receipt bytes in the
        # producer: the offline verifier must enforce the same invariant.
        empty = b""
        row = record(der=empty)
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(manifest([row]),
                            files=[(row["responseFile"], empty)]))

    def test_modified_manifest_hash_is_rejected(self):
        m = manifest([record(TokenSha256Hex="0" * 64)])
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(m))

    def test_missing_extra_and_duplicate_member_names_are_rejected(self):
        name = record()["responseFile"]
        for raw in (
            build_zip(files=[]),
            build_zip(extras=[("tokens/extra.tsr", DER)]),
            build_zip(files=[(name, DER), (name, DER)]),
            build_zip(extras=[("../outside.txt", DER)]),
        ):
            with self.subTest(raw_size=len(raw)):
                with self.assertRaises(verifier.ExportVerificationError):
                    check(raw)

    @staticmethod
    def _replace_zip_compression_method(raw: bytes, name: str, method: int) -> bytes:
        """Mutate both local and central method IDs; keep file bytes/CRC intact.

        This creates a realistic unsupported-method ZIP, not merely a local
        vs central header mismatch that zipfile would already reject.
        """
        modified = bytearray(raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            member = archive.getinfo(name)
            loc = member.header_offset
            assert modified[loc:loc+4] == b"PK\x03\x04"
            struct.pack_into("<H", modified, loc + 8, method)
        position = 0
        found = False
        while True:
            position = modified.find(b"PK\x01\x02", position)
            if position == -1:
                break
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", modified, position + 28)
            central_name = bytes(modified[position + 46:position + 46 + name_len]).decode("utf-8")
            if central_name == name:
                struct.pack_into("<H", modified, position + 10, method)
                found = True
                break
            position += 46 + name_len + extra_len + comment_len
        assert found, "Fixture could not locate target central ZIP header"
        return bytes(modified)

    def test_unknown_compression_in_both_headers_fails_closed_without_traceback(self):
        member = record()["responseFile"]
        modified = self._replace_zip_compression_method(build_zip(), member, 99)
        # The old RuntimeError catch already includes NotImplementedError.
        # The guard should still reject unknown methods via metadata before
        # entering the decompressor, with the same generic CLI error.
        with self.assertRaises(verifier.ExportVerificationError):
            check(modified)

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-export.zip"
            path.write_bytes(modified)
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                code = verifier.main([str(path)])
            self.assertEqual(1, code)
            self.assertEqual("", output.getvalue())
            self.assertIn("FAILED", errors.getvalue())
            self.assertNotIn(str(path), errors.getvalue())

    # #165 / ADR 0123: stock zipfile can read an ordinary ZIP with
    # unreferenced bytes *inside* the physical member range. The current
    # seekable .NET v1 layout should leave no inter-member or final gap.
    @staticmethod
    def _insert_opaque_gap_after_member(raw: bytes, member_name: str) -> bytes:
        opaque = b"PRIVATE-UNREFERENCED-INTERNAL-GAP-165"
        assert raw[-22:-18] == b"PK\x05\x06"
        original_central = struct.unpack_from("<I", raw, len(raw) - 22 + 16)[0]
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            target = archive.getinfo(member_name)
            members = archive.infolist()
            assert archive.start_dir == original_central
            local = target.header_offset
        assert raw[local:local + 4] == b"PK\x03\x04"
        local_name, local_extra = struct.unpack_from("<HH", raw, local + 26)
        insert_at = local + 30 + local_name + local_extra + target.compress_size
        assert 0 < insert_at <= original_central

        changed = bytearray(raw[:insert_at] + opaque + raw[insert_at:])
        new_central = original_central + len(opaque)
        new_eocd = len(changed) - 22
        struct.pack_into("<I", changed, new_eocd + 16, new_central)
        cursor = new_central
        for _ in members:
            assert changed[cursor:cursor + 4] == b"PK\x01\x02"
            name_len, extra_len, comment_len = struct.unpack_from(
                "<HHH", changed, cursor + 28)
            offset = struct.unpack_from("<I", changed, cursor + 42)[0]
            if offset >= insert_at:  # later local headers physically moved
                struct.pack_into("<I", changed, cursor + 42,
                                 offset + len(opaque))
            cursor += 46 + name_len + extra_len + comment_len
        assert cursor == new_eocd
        return bytes(changed)

    def test_internal_unreferenced_zip_gaps_are_denied_despite_intact_members(self):
        for base, after, count in (
            (build_zip(), "manifest.json", 1),
            (build_zip(), record()["responseFile"], 1),
            (build_zip(manifest([])), "manifest.json", 0),
        ):
            with self.subTest(after=after, receipts=count):
                self.assertEqual(count, check(base))
                changed = self._insert_opaque_gap_after_member(base, after)
                with zipfile.ZipFile(io.BytesIO(changed), "r") as archive:
                    self.assertEqual("temporalmark-period-export-v1",
                                     json.loads(archive.read("manifest.json"))["format"])
                    if count:
                        self.assertEqual(DER, archive.read(record()["responseFile"]))
                    self.assertEqual(count + 1, len(archive.infolist()))
                with self.assertRaises(verifier.ExportVerificationError):
                    check(changed)

    def test_internal_gap_cli_is_generic_and_does_not_echo_payload_or_path(self):
        changed = self._insert_opaque_gap_after_member(
            build_zip(), record()["responseFile"])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-internal-gap-export.zip"
            path.write_bytes(changed)
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = verifier.main([str(path)])
            self.assertEqual(1, status)
            self.assertEqual("", output.getvalue())
            self.assertIn("FAILED", errors.getvalue())
            self.assertNotIn(str(path), errors.getvalue())
            self.assertNotIn(ORG, errors.getvalue())
            self.assertNotIn("PRIVATE-UNREFERENCED", errors.getvalue())

    # #164 / ADR 0122: local CRC/length DWORDs are ignored by Python's
    # ordinary ZipFile.read(), even when they contradict the central directory.
    # Keep the central directory, manifest, original DER and hashes untouched.
    @staticmethod
    def _change_only_local_crc_or_size(raw: bytes, name: str,
                                       local_field_offset: int) -> bytes:
        assert local_field_offset in (14, 18, 22)
        modified = bytearray(raw)
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            local_offset = archive.getinfo(name).header_offset
        assert modified[local_offset:local_offset + 4] == b"PK\x03\x04"
        assert struct.unpack_from("<I", modified,
                                  local_offset + local_field_offset)[0] != 0
        struct.pack_into("<I", modified, local_offset + local_field_offset, 0)
        return bytes(modified)

    def test_local_crc_and_sizes_must_match_central_before_any_decompression(self):
        base = build_zip()
        self.assertEqual(1, check(base))
        for name in ("manifest.json", record()["responseFile"]):
            for offset, field in ((14, "crc32"), (18, "compressed size"),
                                  (22, "uncompressed size")):
                with self.subTest(member=name, local_field=field):
                    altered = self._change_only_local_crc_or_size(base, name, offset)
                    # These are six genuine missing-denial fixtures:
                    # stock zipfile still reads the original, CRC-clean members.
                    with zipfile.ZipFile(io.BytesIO(altered), "r") as archive:
                        self.assertEqual(DER, archive.read(record()["responseFile"]))
                        self.assertEqual("temporalmark-period-export-v1",
                                         json.loads(archive.read("manifest.json"))["format"])
                    with self.assertRaises(verifier.ExportVerificationError):
                        check(altered)

    def test_mismatched_local_crc_cli_failure_never_leaks_private_values(self):
        altered = self._change_only_local_crc_or_size(
            build_zip(), "manifest.json", 14)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tenant-secret-export.zip"
            path.write_bytes(altered)
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                exit_code = verifier.main([str(path)])
            self.assertEqual(1, exit_code)
            self.assertEqual("", output.getvalue())
            self.assertIn("FAILED", errors.getvalue())
            self.assertNotIn(str(path), errors.getvalue())
            self.assertNotIn(ORG, errors.getvalue())

    def test_data_descriptor_flag_not_in_current_seekable_v1_profile(self):
        # A one-member valid zero-record archive makes the central-header
        # mutation unambiguous. Both flags match: ADR 0078 doesn't deny it.
        base = build_zip(manifest([]))
        self.assertEqual(0, check(base))
        altered = bytearray(base)
        central_offset = altered.rfind(b"PK\x01\x02")
        self.assertGreater(central_offset, 0)
        self.assertEqual(b"PK\x03\x04", altered[:4])
        struct.pack_into("<H", altered, 6, 0x0008)
        struct.pack_into("<H", altered, central_offset + 8, 0x0008)
        with zipfile.ZipFile(io.BytesIO(altered), "r") as archive:
            self.assertEqual("temporalmark-period-export-v1",
                             json.loads(archive.read("manifest.json"))["format"])
        with self.assertRaises(verifier.ExportVerificationError):
            check(bytes(altered))

    @staticmethod
    def _change_only_local_header_short(raw: bytes, name: str,
                                       field_offset: int, value: int) -> bytes:
        # Source-only RED-first #109: central directory, DER, CRC, manifest
        # and member bytes remain unchanged. Do not accidentally modify the
        # central ZIP header or fail test-fixture construction.
        modified = bytearray(raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            member = archive.getinfo(name)
            offset = member.header_offset
        assert modified[offset:offset + 4] == b"PK\x03\x04"
        assert field_offset in (6, 8)  # flags or method in local header
        struct.pack_into("<H", modified, offset + field_offset, value)
        return bytes(modified)

    def test_local_only_unknown_method_disagrees_with_central_v1_decompression(self):
        for member in ("manifest.json", record()["responseFile"]):
            with self.subTest(member=member):
                raw = build_zip()
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    self.assertEqual(zipfile.ZIP_DEFLATED,
                                     archive.getinfo(member).compress_type)
                altered = self._change_only_local_header_short(
                    raw, member, 8, 99)
                with self.assertRaises(verifier.ExportVerificationError):
                    check(altered)

    def test_local_only_flag_differences_are_not_accepted_from_either_member(self):
        for member in ("manifest.json", record()["responseFile"]):
            for conflicting_flags in (0x0001, 0x0008, 0x0800):
                with self.subTest(member=member, local_flags=conflicting_flags):
                    raw = build_zip()
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        self.assertEqual(0, archive.getinfo(member).flag_bits)
                    altered = self._change_only_local_header_short(
                        raw, member, 6, conflicting_flags)
                    with self.assertRaises(verifier.ExportVerificationError):
                        check(altered)

    def test_local_central_mismatch_cli_error_is_generic_not_path_leak(self):
        altered = self._change_only_local_header_short(
            build_zip(), record()["responseFile"], 8, 99)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tenant-private-export.zip"
            path.write_bytes(altered)
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = verifier.main([str(path)])
            self.assertEqual(1, status)
            self.assertEqual("", output.getvalue())
            self.assertIn("FAILED", errors.getvalue())
            self.assertNotIn(str(path), errors.getvalue())
            self.assertNotIn(ORG, errors.getvalue())

    def test_known_but_not_v1_bzip2_member_is_rejected(self):
        member = zipfile.ZipInfo(record()["responseFile"])
        member.compress_type = zipfile.ZIP_BZIP2
        # Even a supported compression algorithm is not authorized by the
        # current .NET v1 export profile.
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(files=[(member, DER)]))

    def test_unix_special_files_are_not_ordinary_tsrs(self):
        for file_type in (
            stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR,
            stat.S_IFBLK, stat.S_IFDIR, stat.S_IFLNK
        ):
            member = zipfile.ZipInfo(record()["responseFile"])
            member.create_system = 3
            member.external_attr = (file_type | 0o600) << 16
            with self.subTest(file_type=file_type):
                with self.assertRaises(verifier.ExportVerificationError):
                    check(build_zip(files=[(member, DER)]))

    def test_regular_stored_and_deflated_zip_members_still_pass(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            member = zipfile.ZipInfo(record()["responseFile"])
            member.create_system = 3
            member.compress_type = method
            member.external_attr = (stat.S_IFREG | 0o600) << 16
            with self.subTest(method=method):
                self.assertEqual(1, check(build_zip(files=[(member, DER)])))

    def test_symlink_zip_entry_is_rejected_even_without_extraction(self):
        info = zipfile.ZipInfo("tokens/symlink.tsr")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(extras=[(info, b"destination")]))

    def test_duplicated_manifest_json_key_is_rejected(self):
        raw = json.dumps(manifest(), separators=(",", ":"))
        tampered = raw.replace(
            '"count":1,', '"count":1,"count":1,')
        self.assertNotEqual(raw, tampered)
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(raw_manifest=tampered.encode()))

    def test_missing_schema_bad_count_and_duplicate_ids_are_rejected(self):
        duplicate = record()
        cases = [
            manifest(format="something-else"),
            manifest(count=True),
            manifest(count=2),
            manifest(entries=[duplicate, duplicate]),
            manifest(entries=[{k: v for k, v in record().items() if k != "HashAlgorithmOid"}]),
            manifest(organizationId="not-a-uuid"),
        ]
        for m in cases:
            with self.subTest(m=m.get("count")):
                with self.assertRaises(verifier.ExportVerificationError):
                    check(build_zip(m))

    def test_declared_path_must_match_exact_record_id_and_safe_zip_layout(self):
        m = manifest([record(responseFile="tokens/../../escape.tsr")])
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(m))

    def test_issuance_must_be_utc_within_half_open_period_including_tick_precision(self):
        cases = [
            manifest([record(IssuedUtc="2026-12-01T00:00:00+00:00")]),
            manifest([record(IssuedUtc="2026-10-31T23:59:59.9999999+00:00")]),
            manifest([record(IssuedUtc="2026-11-15T09:00:00+02:00")]),
            manifest([record(IssuedUtc="2026-11-15T09:00:00")]),
            manifest([record(IssuedUtc="2026-11-15T09:00:00.12345678+00:00")]),
            manifest([record(IssuedUtc=START)],
                     fromUtc="2026-11-01T00:00:00.0000001+00:00"),
        ]
        for m in cases:
            with self.subTest(m=m["entries"][0]["IssuedUtc"]):
                with self.assertRaises(verifier.ExportVerificationError):
                    check(build_zip(m))
        self.assertEqual(1, check(build_zip(manifest(
            [record(IssuedUtc="2026-11-01T00:00:00.0000001+00:00")],
            fromUtc="2026-11-01T00:00:00.0000001+00:00"))))

    def test_noncanonical_digest_and_wrong_algorithm_are_rejected(self):
        original = record()["DigestBase64"]
        for row in (
            record(DigestBase64=original + "\n"),
            record(DigestBase64=original[:-2] + "B="),
            record(HashAlgorithmOid="1.3.14.3.2.26"),
        ):
            with self.assertRaises(verifier.ExportVerificationError):
                check(build_zip(manifest([row])))

    # #182 / ADR 0140: establish strict Python v1 behavior independently
    # of the .NET new-write and historical-read REDs. Python .strip()
    # treats U+001C–U+001F as whitespace whereas .NET Char.IsWhiteSpace
    # does not. A visible identifier with an embedded separator is valid.
    def test_c0_separator_only_policy_and_provider_are_denied(self):
        for field in ("PolicyOid", "ProviderId"):
            for source in ("\u001c", "\u001d", "\u001e", "\u001f",
                           " \u001c\u00a0\u001f"):
                with self.subTest(field=field, source=ord(source[-1])):
                    self.assertFalse(bool(source.strip()))
                    with self.assertRaises(verifier.ExportVerificationError):
                        check(build_zip(manifest([record(**{field: source})])))

    def test_visible_policy_and_provider_with_embedded_c0_are_preserved(self):
        row = record(PolicyOid="1.\u001c2.3", ProviderId="ISSUER\u001fVISIBLE")
        self.assertEqual(1, check(build_zip(manifest([row]))))

    # #183 / ADR 0141. The current .NET v1 producer first writes the
    # manifest then TSR members in (IssuedUtc, canonical Id) SQL order.
    # Distinct tenant-owned original SHA-consistent DER+manifest rows with
    # reversed chronology or physical member order MUST be refused, not
    # silently accepted merely because the unordered ZIP bag is consistent.
    @staticmethod
    def _canonical_timeline_rows():
        original = record(
            rid="11111111-1111-4111-8111-111111111111",
            IssuedUtc="2026-11-15T09:00:00.1234567+00:00")
        tie = record(
            rid="22222222-2222-4222-8222-222222222222",
            IssuedUtc=original["IssuedUtc"])
        later = record(
            rid="33333333-3333-4333-8333-333333333333",
            IssuedUtc="2026-11-15T09:00:00.1234568+00:00")
        return original, tie, later

    def test_current_v1_accepts_sorted_same_tick_and_different_tick_records(self):
        rows = self._canonical_timeline_rows()
        self.assertEqual(3, check(build_zip(manifest(list(rows)))))
        self.assertEqual(2, check(build_zip(manifest(list(rows[:2])))))

    def test_reversed_utc_manifest_rows_are_denied_even_with_valid_der_and_members(self):
        first, tie, later = self._canonical_timeline_rows()
        # All original IDs, DER hashes, UTC period, ZIP entries and bytes
        # are valid. The only mutation is the manifest timeline.
        original = build_zip(manifest([later, first, tie]))
        with self.assertRaises(verifier.ExportVerificationError):
            check(original)

    def test_same_tick_reversed_uuid_tie_is_denied(self):
        first, tie, _ = self._canonical_timeline_rows()
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(manifest([tie, first])))

    def test_physical_tsr_order_must_match_strictly_ordered_manifest(self):
        first, tie, later = self._canonical_timeline_rows()
        rows = [first, tie, later]
        files = [(row["responseFile"], DER) for row in reversed(rows)]
        # Generic Python zipfile finds all names and hashes; current v1
        # .NET producer writes manifest then physically ordered receipts.
        raw = build_zip(manifest(rows), files=files)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(DER, archive.read(first["responseFile"]))
            self.assertEqual(DER, archive.read(later["responseFile"]))
        with self.assertRaises(verifier.ExportVerificationError):
            check(raw)

    def test_manifest_must_be_physically_first_v1_member(self):
        first, tie, _ = self._canonical_timeline_rows()
        rows = [first, tie]
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(first["responseFile"], DER)
            archive.writestr("manifest.json", json.dumps(
                manifest(rows), separators=(",", ":")).encode("utf-8"))
            archive.writestr(tie["responseFile"], DER)
        with self.assertRaises(verifier.ExportVerificationError):
            check(raw.getvalue())

    def test_reordered_receipts_cli_failure_redacts_tenant_and_names(self):
        first, tie, later = self._canonical_timeline_rows()
        rows = [first, tie, later]
        raw = build_zip(manifest(rows),
                        files=[(row["responseFile"], DER) for row in reversed(rows)])
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "private-tenant-archive.zip"
            source.write_bytes(raw)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                result = verifier.main([str(source)])
            self.assertEqual(1, result)
            self.assertEqual("", out.getvalue())
            self.assertIn("FAILED", err.getvalue())
            self.assertNotIn(ORG, err.getvalue())
            self.assertNotIn(str(source), err.getvalue())
            self.assertNotIn(first["responseFile"], err.getvalue())
            self.assertNotIn(tie["responseFile"], err.getvalue())

    # #184 / ADR 0142: .NET/PG17 v1 admission limits EACH original
    # registry text field to 16KiB UTF8 and their whole export batch to
    # 2MiB. JSON manifest 8MiB and compressed ZIP 80MiB are SEPARATE
    # budgets: repetitive oversized source strings easily fit both.
    # No original text is normalized or trimmed to satisfy a byte limit.
    @staticmethod
    def _source_metadata_batch(count: int, policy_size: int):
        return [
            record(
                rid=f"{i + 1:08x}-0000-4000-8000-000000000000",
                PolicyOid="P" * policy_size)
            for i in range(count)
        ]

    def test_nonblank_policy_16385_original_utf8_bytes_refused(self):
        row = record(PolicyOid="P" * (16 * 1024 + 1))
        self.assertEqual(16 * 1024 + 1, len(row["PolicyOid"].encode("utf-8")))
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(manifest([row])))

    def test_nonblank_provider_16385_original_utf8_bytes_refused(self):
        row = record(ProviderId="V" * (16 * 1024 + 1))
        self.assertEqual(16 * 1024 + 1, len(row["ProviderId"].encode("utf-8")))
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(manifest([row])))

    def test_multibyte_utf8_source_length_not_python_character_count(self):
        for field in ("PolicyOid", "ProviderId"):
            value = "é" * 8193
            self.assertLess(len(value), 16 * 1024)
            self.assertGreater(len(value.encode("utf-8")), 16 * 1024)
            with self.subTest(field=field), self.assertRaises(
                    verifier.ExportVerificationError):
                check(build_zip(manifest([record(**{field: value})])))

    def test_export_batch_original_text_total_over_2mib_refused(self):
        # 128 individually admissible, distinct same-UTC chronological
        # rows with an exact 16KiB policy already exceed 2MiB once the
        # three additional mandatory text fields are counted. This
        # manifest is <8MiB JSON and compressed ZIP is <80MiB.
        rows = self._source_metadata_batch(128, 16 * 1024)
        raw_manifest = json.dumps(manifest(rows), separators=(",", ":")).encode()
        self.assertLess(len(raw_manifest), 8 * 1024 * 1024)
        raw = build_zip(manifest(rows))
        self.assertLess(len(raw), 80 * 1024 * 1024)
        with self.assertRaises(verifier.ExportVerificationError):
            check(raw)

    def test_original_text_budget_cli_denial_does_not_echo_private_values(self):
        secret = "CONFIDENTIAL-POLICY-" + ("P" * 17_000)
        source = build_zip(manifest([record(PolicyOid=secret)]))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tenant-a-private-period.zip"
            path.write_bytes(source)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                exit_code = verifier.main([str(path)])
            self.assertEqual(1, exit_code)
            self.assertEqual("", out.getvalue())
            self.assertIn("FAILED", err.getvalue())
            for private in ("CONFIDENTIAL-POLICY", ORG, RID,
                            "tenant-a-private-period.zip"):
                self.assertNotIn(private, err.getvalue())

    def test_exact_16k_original_utf8_field_is_still_valid(self):
        rows = [
            record(PolicyOid="P" * (16 * 1024),
                   ProviderId="V" * (16 * 1024),
                   EvidenceReference="operator-controlled-original"),
            record(rid="22222222-2222-4222-8222-222222222222",
                   PolicyOid="é" * 8192,
                   ProviderId="VISIBLE\u001fORIGINAL")
        ]
        self.assertEqual(16 * 1024, len(rows[1]["PolicyOid"].encode("utf-8")))
        self.assertEqual(2, check(build_zip(manifest(rows))))

    def test_original_utf8_batch_near_but_under_2mib_remains_valid(self):
        # 127 * 16KiB + other fixed fields is <2MiB. Avoid canonical
        # identity and time changes: the synthetic values are in valid
        # ascending same-UTC UUID order with original signed-test-only DER.
        rows = self._source_metadata_batch(127, 16 * 1024)
        source_text_bytes = sum(
            len(row[field].encode("utf-8"))
            for row in rows
            for field in ("HashAlgorithmOid", "DigestBase64",
                          "PolicyOid", "ProviderId")
        )
        self.assertLess(source_text_bytes, 2 * 1024 * 1024)
        self.assertEqual(127, check(build_zip(manifest(rows))))

    # #185 / ADR 0143: the current .NET v1 exporter writes a central
    # directory in exactly the same order as the chronological manifest
    # and physical local headers. Generic ZipFile tolerates a different
    # central RECORD order and reads all original bytes successfully.
    @staticmethod
    def _permute_central_records_without_changing_any_other_bytes(
            original: bytes, permutation: tuple[int, ...]) -> bytes:
        with zipfile.ZipFile(io.BytesIO(original)) as archive:
            previous_names = archive.namelist()
            offsets = {info.filename: info.header_offset
                       for info in archive.infolist()}
            expected_raw = {name: archive.read(name)
                            for name in previous_names}
            directory_start = archive.start_dir
        assert len(permutation) == len(previous_names)
        assert sorted(permutation) == list(range(len(previous_names)))
        assert original[-22:-18] == b"PK\x05\x06"  # classic no-comment EOCD
        size, offset = struct.unpack_from(
            "<II", original, len(original) - 22 + 12)
        assert directory_start == offset
        position = offset
        records = []
        for _ in previous_names:
            assert original[position:position + 4] == b"PK\x01\x02"
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", original, position + 28)
            end = position + 46 + name_length + extra_length + comment_length
            assert end <= offset + size
            records.append(original[position:end])
            position = end
        assert position == offset + size
        reordered = (
            original[:offset] +
            b"".join(records[index] for index in permutation) +
            original[position:])
        assert len(reordered) == len(original)
        assert reordered[:offset] == original[:offset]
        assert reordered[position:] == original[position:]
        with zipfile.ZipFile(io.BytesIO(reordered)) as archive:
            assert archive.namelist() == [
                previous_names[index] for index in permutation]
            assert {i.filename: i.header_offset for i in archive.infolist()} == offsets
            for name, raw in expected_raw.items():
                assert archive.read(name) == raw
        return reordered

    def test_canonical_central_and_local_manifest_order_accepts_two_receipts(self):
        first, tie, _ = self._canonical_timeline_rows()
        raw = build_zip(manifest([first, tie]))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = ["manifest.json", first["responseFile"], tie["responseFile"]]
            self.assertEqual(names, archive.namelist())
            self.assertEqual(names, [i.filename for i in sorted(
                archive.infolist(), key=lambda entry: entry.header_offset)])
        self.assertEqual(2, check(raw))

    def test_central_receipt_before_manifest_is_denied_even_if_locals_correct(self):
        first, tie, _ = self._canonical_timeline_rows()
        original = build_zip(manifest([first, tie]))
        tampered = self._permute_central_records_without_changing_any_other_bytes(
            original, (1, 0, 2))
        self.assertEqual(2, check(original))
        with self.assertRaises(verifier.ExportVerificationError):
            check(tampered)

    def test_central_tsr_swap_is_denied_even_if_local_manifest_order_correct(self):
        first, tie, _ = self._canonical_timeline_rows()
        original = build_zip(manifest([first, tie]))
        tampered = self._permute_central_records_without_changing_any_other_bytes(
            original, (0, 2, 1))
        self.assertEqual(2, check(original))
        with self.assertRaises(verifier.ExportVerificationError):
            check(tampered)

    def test_central_order_denial_cli_is_generic_and_private_metadata_is_absent(self):
        first, tie, _ = self._canonical_timeline_rows()
        altered = self._permute_central_records_without_changing_any_other_bytes(
            build_zip(manifest([first, tie])), (0, 2, 1))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tenant-confidential-original-der.zip"
            path.write_bytes(altered)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = verifier.main([str(path)])
            self.assertEqual(1, code)
            self.assertEqual("", out.getvalue())
            self.assertIn("FAILED", err.getvalue())
            for secret in (ORG, first["Id"], tie["Id"],
                           first["responseFile"], tie["responseFile"],
                           str(path), "tenant-confidential"):
                self.assertNotIn(secret, err.getvalue())

    def test_untrusted_qualified_state_claim_fails_closed(self):
        for state in ("VerifiedQualifiedExternal", "VerifiedQualifiedOwn", "VerifiedNonQualified"):
            with self.subTest(state=state):
                with self.assertRaises(verifier.ExportVerificationError):
                    check(build_zip(manifest([record(validationState=state)])))

    def test_oversized_member_and_cumulative_65_mib_are_rejected(self):
        large = b"\x00" * (1024 * 1024 + 1)
        large_record = record(der=large)
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(manifest([large_record]),
                            files=[(large_record["responseFile"], large)]))

        one_mib = b"\x00" * (1024 * 1024)
        rows = []
        files = []
        for i in range(65):
            rid = f"{i+1:08x}-1111-4111-8111-111111111111"
            row = record(der=one_mib, rid=rid)
            rows.append(row)
            files.append((row["responseFile"], one_mib))
        with self.assertRaises(verifier.ExportVerificationError):
            check(build_zip(manifest(rows), files=files))

    def test_exactly_one_mib_der_is_accepted(self):
        data = b"\x00" * (1024 * 1024)
        row = record(der=data)
        self.assertEqual(1, check(build_zip(manifest([row]),
            files=[(row["responseFile"], data)])))


if __name__ == "__main__":
    unittest.main()
