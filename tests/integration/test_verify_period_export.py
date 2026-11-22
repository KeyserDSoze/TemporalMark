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
