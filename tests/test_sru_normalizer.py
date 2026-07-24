from datetime import datetime

from modules.normalizer.normalizers.sru import SRUNormalizer


def _base_record():
    return {
        "artifact_type": "sru", "table": "network-table", "record_id": 7,
        "database": "SRUDB.dat", "database_format_version": 0x620,
        "source_path": "input/KAPE_OUTPUT/C/Windows/System32/sru/SRUDB.dat",
        "TimeStamp": datetime(2025, 3, 7, 11, 0), "application": "powershell.exe",
        "application_id": 12, "user_sid": "S-1-5-21-1000", "user_id": 4,
    }


def test_sru_normalizes_network_usage_with_accounting_semantics():
    record = {**_base_record(), "BytesSent": 120, "BytesRecvd": 850, "InterfaceLuid": 10, "L2ProfileId": 3}
    event = SRUNormalizer().normalize(record)[0]

    assert event["event_type"] == "application_network_usage"
    assert event["bytes_sent"] == 120
    assert event["total_bytes"] == 970
    assert event["timestamp_semantics"] == "sru_accounting_interval"
    assert "table:network-table" in event["evidence"]


def test_sru_normalizes_resources_and_connectivity_without_guessing_energy():
    resource = {
        **_base_record(), "ForegroundCycleTime": 20, "BackgroundCycleTime": 5,
        "ForegroundBytesRead": 3, "BackgroundBytesRead": 2,
        "ForegroundBytesWritten": 4, "BackgroundBytesWritten": 1,
    }
    connectivity = {**_base_record(), "ConnectedTime": 12, "ConnectStartTime": datetime(2025, 3, 7, 10, 59)}

    assert SRUNormalizer().normalize(resource)[0]["total_cycle_time"] == 25
    assert SRUNormalizer().normalize(connectivity)[0]["event_type"] == "network_connectivity"
    assert SRUNormalizer().normalize({**_base_record(), "Energy Data": b"opaque"}) == []
