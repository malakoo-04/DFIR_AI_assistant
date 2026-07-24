from modules.normalizer.mapping import NORMALIZER_MAPPING


def _merge_evidence(existing_event: dict, new_evidence: dict) -> None:
    """Fold a duplicate record's evidence into an already-kept event.

    evidence is always a dict (see create_event()). Unlike a flat tag list,
    dict fields can't be deduplicated key-by-key: two merged records can
    legitimately disagree on fields like "key_path" or "value_name" while
    still describing the same forensic fact. Instead of overwriting or
    guessing, every distinct evidence dict encountered for a merged identity
    is preserved as its own entry under "occurrences", so nothing about
    *where* the fact came from is lost.
    """
    existing_evidence = existing_event.setdefault("evidence", {})

    if not new_evidence or new_evidence == existing_evidence:
        return

    occurrences = existing_evidence.setdefault("occurrences", [])
    if new_evidence not in occurrences:
        occurrences.append(new_evidence)


class Normalizer:

    def normalize(self, records):
        normalized = []
        recentdocs_index = {}
        usb_device_index = {}
        usn_index = {}

        for record in records:
            if not isinstance(record, dict):
                print(f"[NORMALIZER ERROR] Skipping non-dictionary record: {type(record).__name__}")
                continue

            artifact_type = record.get("artifact_type")

            normalizer = NORMALIZER_MAPPING.get(artifact_type)

            if normalizer:
                try:
                    events = normalizer.normalize(record)
                    for event in events or []:
                        if event.get("artifact_type") == "usn":
                            event_type = event.get("event_type")
                            frn = event.get("file_reference")
                            # FRNs include the NTFS sequence number, making a
                            # suitable identity for a single file instance.
                            if event_type in {"file_creation", "file_deletion", "file_modification"}:
                                identity = (event.get("source_file"), event_type, frn)
                            else:  # Preserve distinct rename destinations.
                                identity = (
                                    event.get("source_file"), event_type, frn,
                                    event.get("parent_reference"), event.get("file_name"),
                                )

                            existing = usn_index.get(identity)
                            if existing is None:
                                event["usn_record_count"] = 1
                                usn_index[identity] = event
                                normalized.append(event)
                                continue

                            existing["usn_record_count"] += 1
                            existing["last_usn"] = event.get("usn")
                            existing["last_usn_timestamp"] = event.get("timestamp")
                            existing_flags = existing.setdefault("reason_flags", [])
                            for flag in event.get("reason_flags", []):
                                if flag not in existing_flags:
                                    existing_flags.append(flag)
                            related_usns = existing.setdefault("related_usns", [existing.get("usn")])
                            if len(related_usns) < 20 and event.get("usn") not in related_usns:
                                related_usns.append(event.get("usn"))
                            continue

                        if event.get("event_type") == "usb_device_connected":
                            identity = (
                                event.get("source_file"),
                                event.get("device_instance_id"),
                            )
                            existing = usb_device_index.get(identity)
                            if existing is None:
                                usb_device_index[identity] = event
                                normalized.append(event)
                                continue
                            _merge_evidence(existing, event.get("evidence", {}))
                            continue

                        if event.get("event_type") != "document_opened":
                            normalized.append(event)
                            continue

                        # RecentDocs root and extension subkeys can contain the
                        # same MRU item. Keep one timeline event for a matching
                        # source/path/key-write time and retain every key as evidence.
                        identity = (
                            event.get("source_file"),
                            event.get("user"),
                            event.get("document_path"),
                            event.get("timestamp"),
                        )
                        existing = recentdocs_index.get(identity)
                        if existing is None:
                            recentdocs_index[identity] = event
                            normalized.append(event)
                            continue

                        registry_key = event.get("registry_key")
                        if registry_key:
                            keys = existing.setdefault(
                                "related_registry_keys",
                                [existing.get("registry_key")],
                            )
                            if registry_key not in keys:
                                keys.append(registry_key)
                        _merge_evidence(existing, event.get("evidence", {}))
                except Exception as exc:
                    source = record.get("source_path", "unknown source")
                    print(f"[NORMALIZER ERROR] {artifact_type} ({source}): {exc}")

        return normalized