from modules.normalizer.normalizer import Normalizer
from modules.timeline.builder import TimelineBuilder


def _usn(reason, usn, timestamp):
    return {
        "artifact_type": "usn",
        "source_path": "input/KAPE_OUTPUT/C/$Extend/$J",
        "usn": usn,
        "timestamp": timestamp,
        "file_name": "report.docx",
        "frn": 123,
        "parent_frn": 10,
        "reason_code": reason,
        "reason": "USN reason",
        "file_attributes_code": 32,
        "file_attributes": "ARCHIVE",
        "source_info_code": 0,
        "source_info": "",
        "security_id": 0,
        "usn_version_major": 2,
        "usn_version_minor": 0,
    }


def test_usn_writes_are_compacted_and_excluded_from_timeline():
    events = Normalizer().normalize([
        _usn(0x1, 1, "2025-03-07T10:00:00"),
        _usn(0x2, 2, "2025-03-07T10:00:01"),
        _usn(0x4, 3, "2025-03-07T10:00:02"),
    ])

    assert len(events) == 1
    assert events[0]["event_type"] == "file_modification"
    assert events[0]["usn_record_count"] == 3
    assert events[0]["timeline_eligible"] is False
    assert TimelineBuilder().build(events) == []
