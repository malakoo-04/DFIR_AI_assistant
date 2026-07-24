from modules.normalizer.normalizers.usn import USNNormalizer


def _record(reason_code, file_name="malware.exe", attributes=32):
    return {
        "artifact_type": "usn",
        "source_path": "input/KAPE_OUTPUT/C/$Extend/$J",
        "usn": 42,
        "timestamp": "2025-03-07T11:00:00",
        "file_name": file_name,
        "frn": 100,
        "parent_frn": 50,
        "reason_code": reason_code,
        "reason": "USN reason text",
        "file_attributes_code": attributes,
        "file_attributes": "ARCHIVE",
        "source_info_code": 0,
        "source_info": "",
        "security_id": 0,
        "usn_version_major": 2,
        "usn_version_minor": 0,
    }


def test_usn_normalizes_meaningful_file_operations():
    normalizer = USNNormalizer()

    assert normalizer.normalize(_record(0x100))[0]["event_type"] == "file_creation"
    assert normalizer.normalize(_record(0x200))[0]["event_type"] == "file_deletion"
    assert normalizer.normalize(_record(0x2000))[0]["event_type"] == "file_renamed"
    event = normalizer.normalize(_record(0x1))[0]
    assert event["event_type"] == "file_modification"
    assert event["timeline_eligible"] is False
    assert event["timestamp_semantics"] == "usn_record_timestamp"
    assert event["file_reference"] == 100


def test_usn_ignores_noise_and_uninteresting_change_flags():
    normalizer = USNNormalizer()

    assert normalizer.normalize(_record(0x8000)) == []
    assert normalizer.normalize(_record(0x100, "~$Report.docx")) == []
    assert normalizer.normalize(_record(0x100, "folder", attributes=16)) == []
