"""RED-first #107: offline ZIP structural and hash checks, NOT QTSP trust."""
import base64
import hashlib
import io
import json
import stat
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
    def test_current_v1_archive_passes_only_local_consistency(self):
        self.assertEqual(1, check(build_zip()))

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
