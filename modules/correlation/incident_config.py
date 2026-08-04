EDGE_WEIGHTS = {
    "shared_event": 120,
    "shared_entity": 80,
    "same_executable": 15,
    "same_user": 10,
    "temporal_proximity": 5,
}

MIN_EDGE_SCORE = 80

MIN_EDGE_SCORE = 30

# Matches the "proximity" window discussed for edge scoring — kept
# short and undocumented-elsewhere until now, hence the missing
# constant that IncidentGraphBuilder already expected.
TEMPORAL_WINDOW_SECONDS = 300