from modules.normalizer.normalizers.registry import RegistryNormalizer


def test_recentdocs_prefers_a_clean_terminal_filename_and_user_hive():
    raw = "Firefox Installer.exe\x00metadata\x00Firefox Installer.exe\x00".encode("utf-16le")
    record = {
        "artifact_type": "registry",
        "hive": "NTUSER.DAT",
        "user": "ahmed",
        "source_path": "input/KAPE_OUTPUT/C/Users/ahmed/NTUSER.DAT",
        "key_path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "last_written": "2025-03-07T11:00:00",
        "values": [
            {"name": "MRUListEx", "type": "REG_BINARY", "value_data": b""},
            {"name": "0", "type": "REG_BINARY", "value_data": raw},
        ],
    }

    events = RegistryNormalizer().normalize(record)

    assert len(events) == 1
    assert events[0]["document_path"] == "Firefox Installer.exe"
    assert events[0]["user"] == "ahmed"
    assert events[0]["timestamp_semantics"] == "registry_key_last_written"


def test_recentdocs_ignores_machine_hive_configuration_data():
    record = {
        "artifact_type": "registry",
        "hive": "SOFTWARE",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "values": [{"name": "ViewStream", "type": "REG_BINARY", "value_data": b"data"}],
    }

    assert RegistryNormalizer().normalize(record) == []


def test_recentdocs_prefers_full_paths_and_ignores_temporary_files():
    raw = (
        "Firefox.exe\x00"
        "~$Report.docx\x00"
        "C:\\Users\\ahmed\\Desktop\\Firefox.exe\x00"
        "Thumbs.db\x00"
    ).encode("utf-16le")

    assert (
        RegistryNormalizer._extract_recentdocs_document(raw)
        == "C:\\Users\\ahmed\\Desktop\\Firefox.exe"
    )
    assert RegistryNormalizer._extract_recentdocs_document("desktop.ini\x00".encode("utf-16le")) is None


def test_recentdocs_evidence_identifies_hive_value_and_source():
    raw = "C:\\Cases\\events.evtx\x00".encode("utf-16le")
    record = {
        "artifact_type": "registry",
        "hive": "NTUSER.DAT",
        "user": "ahmed",
        "source_path": "input/KAPE_OUTPUT/C/Users/ahmed/NTUSER.DAT",
        "key_path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "values": [{"name": "4", "type": "REG_BINARY", "value_data": raw}],
    }

    event = RegistryNormalizer().normalize(record)[0]
    assert event["evidence"] == [
        "hive:NTUSER.DAT",
        record["key_path"],
        "value:4",
        f"source:{record['source_path']}",
    ]


def test_usbstor_normalizes_a_serial_instance_not_service_keys():
    instance = {
        "artifact_type": "registry",
        "hive": "SYSTEM",
        "source_path": "input/KAPE_OUTPUT/C/Windows/System32/config/SYSTEM",
        "key_path": "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001240916117452",
        "last_written": "2025-03-07T11:00:00",
        "values": [
            {"name": "FriendlyName", "value_data": "SanDisk Ultra USB Device\x00"},
            {"name": "ParentIdPrefix", "value_data": "7&abc&0"},
            {"name": "ContainerID", "value_data": "{11111111-1111-1111-1111-111111111111}"},
            {"name": "ClassGUID", "value_data": "{36FC9E60-C465-11CF-8056-444553540000}"},
            {"name": "Service", "value_data": "USBSTOR"},
        ],
    }
    event = RegistryNormalizer().normalize(instance)[0]

    assert event["event_type"] == "usb_device_connected"
    assert event["vendor"] == "SanDisk"
    assert event["product"] == "Ultra"
    assert event["revision"] == "1.00"
    assert event["serial_number"] == "4C530001240916117452"
    assert event["friendly_name"] == "SanDisk Ultra USB Device"
    assert event["timestamp_semantics"] == "registry_key_last_written"

    service_key = {**instance, "key_path": "ControlSet001\\Control\\USBSTOR\\054C00C1"}
    assert RegistryNormalizer().normalize(service_key) == []
