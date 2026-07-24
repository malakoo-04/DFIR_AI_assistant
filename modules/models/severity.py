from enum import Enum


class Severity(str, Enum):
    """
    Severity level assigned to a correlation.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"