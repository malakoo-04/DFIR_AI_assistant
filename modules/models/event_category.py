from enum import Enum


class EventCategory(str, Enum):

    EXECUTION = "execution"

    FILESYSTEM = "filesystem"

    REGISTRY = "registry"

    NETWORK = "network"

    AUTHENTICATION = "authentication"

    SECURITY = "security"

    SYSTEM = "system"

    BROWSER = "browser"

    PERSISTENCE = "persistence"

    USER_ACTIVITY = "user_activity"

    DEVICE = "device"

    

  

  
