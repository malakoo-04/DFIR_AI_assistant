from datetime import datetime

from modules.sru.builder import SRUSummaryBuilder


def test_sru_builder_aggregates_network_samples_by_application_and_user():
    events = [
        {"artifact_type": "sru", "event_type": "application_network_usage", "application": "chrome.exe", "user_sid": "S-1-5-21-1", "network_interface": 1, "profile_id": 2, "bytes_sent": 10, "bytes_received": 20, "timestamp": datetime(2025, 3, 7, 10)},
        {"artifact_type": "sru", "event_type": "application_network_usage", "application": "chrome.exe", "user_sid": "S-1-5-21-1", "network_interface": 1, "profile_id": 2, "bytes_sent": 30, "bytes_received": 40, "timestamp": datetime(2025, 3, 7, 11)},
    ]
    summary = SRUSummaryBuilder().build(events)["network_usage"][0]

    assert summary["total_uploaded"] == 40
    assert summary["total_downloaded"] == 60
    assert summary["samples"] == 2
