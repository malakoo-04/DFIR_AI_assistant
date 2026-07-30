EDGE_WEIGHTS = {
    "shared_event": 100,
    "shared_entity": 70,
    "same_executable": 30,
    "same_user": 15,
    "temporal_proximity": 10,
}

MIN_EDGE_SCORE = 30

# Matches the "proximity" window discussed for edge scoring — kept
# short and undocumented-elsewhere until now, hence the missing
# constant that IncidentGraphBuilder already expected.
TEMPORAL_WINDOW_SECONDS = 300