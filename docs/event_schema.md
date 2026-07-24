the objective of this schema is to ensure that every component reasons over a consistent set of fields regardless of the original forensic artifact 
Event Structure:
{
    "artifact_type": ...,
    "event_type": ...,
    "category": ...,

    "timestamp": ...,

    "object_name": ...,
    "object_path": ...,

    "related_objects": [...],

    "user": ...,
    "computer": ...,

    "description": ...,

    "confidence": ...,

    "evidence": {...},

    "source_file": ...,

    "raw_data": {...},
}
TOP_LEVEL FIELDS:
The required fields:

artifact_type:Source forensic artifact(Prefetch, EVTX, Registry, MFT, etc.)
event_type:Standardized forensic event type
category:high-level event category
timestamp:Timestamp associated with the event
description:Human-readable description of the event
source_file:Original artifact file from which the event was extracted
raw_data:Original parser output preserved for traceability

Optional Fields:
object_name:Primary forensic object (file name, process name, registry value, task name, URL title, etc.)
object_path:Path, URL, registry path, executable path, or equivalent
related_objects:Additional objects related to the event
user:User associated with the event
computer:Computer name
confidence:confidence score assigned by the normalize

Evidence:

The evidence dictionary stores artifact-specific forensic information that enriches the event.
Evidence should contain information that:
-explains why the event exists,
-is useful during forensic analysis,
-is not already represented by a first-class event field.

Confidence:

confidence expresses how strongly the artifact supports the inferred event.

1.00:Direct forensic evidence with virtually no ambiguity
0.95:Strong evidence with minimal uncertainty
0.80:Moderate confidence
0.60:Weak indication requiring correlation
<0.50:Low-confidence hypothesis

Confidence reflects the reliability of the forensic interpretation,not the integrity of the artifact itself.

Design Principles

The event model follows a small set of architectural principles:

1-One canonical representation. Every artifact is normalized into the same event structure.
2-No duplicated information. First-class fields must not be repeated inside evidence.
3-Self-contained events. Each event should contain enough information to be understood independently.
4-Traceability first. Every event preserves its origin through source_file and raw_data.
5-Correlation-friendly design. Frequently queried attributes (e.g., hashes, IDs, references) should be promoted to top-level fields whenever appropriate.
6-Artifact-specific details belong in evidence. The evidence dictionary enriches the event without redefining its core identity.