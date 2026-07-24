from enum import Enum


class EntityType(str, Enum):
    """
    Canonical entity types used by the correlation engine.
    """

    FILE = "file"
    PROCESS = "process"
    REGISTRY = "registry"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"
    USER = "user"
    USB_DEVICE = "usb_device"
    NETWORK = "network"