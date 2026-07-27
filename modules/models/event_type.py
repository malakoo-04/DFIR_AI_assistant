from enum import Enum


class  EventType(str, Enum):

    PROCESS_EXECUTION = "process_execution"

    FILE_CREATION = "file_creation"

    FILE_MODIFICATION = "file_modification"

    FILE_DELETION = "file_deletion"

    FILE_RENAMED = "file_renamed"

    FILE_ACCESS = "file_access"

    NETWORK_CONNECTION = "network_connection"

    USER_LOGON = "user_logon"

    USER_LOGOFF = "user_logoff"

    REGISTRY_MODIFICATION = "registry_modification"

    MALWARE_DETECTION = "malware_detection"

    URL_VISIT = "url_visit"

    FILE_DOWNLOAD = "file_download"

    SUCCESSFUL_LOGON = "successful_logon"

    FAILED_LOGON = "failed_logon"

    PROCESS_TERMINATION = "process_termination"

    LOG_CLEARED = "log_cleared"

    SERVICE_INSTALL = "service_install"

    UNKNOWN_EVENT = "unknown_event"

    SHORTCUT_REFERENCE = "shortcut_reference"

    JUMPLIST_REFERENCE = "jumplist_reference"

    APPLICATION_INVENTORY = "application_inventory"

    PERSISTENCE = "persistence"

    SERVICE_CREATED = "service_created"

    DOCUMENT_OPENED = "document_opened"

    USB_DEVICE_CONNECTED = "usb_device_connected"

    APPLICATION_NETWORK_USAGE = "application_network_usage"

    APPLICATION_RESOURCE_USAGE = "application_resource_usage"

    APPLICATION_ENERGY_USAGE = "application_energy_usage"

    NETWORK_CONNECTIVITY = "network_connectivity"

    DEFENDER_SERVICE_STARTED = "defender_service_started"

    DEFENDER_SERVICE_STOPPED = "defender_service_stopped"

    DEFENDER_PLATFORM_UPDATE = "defender_platform_update"

    DEFENDER_INFORMATION = "defender_information"

    DEFENDER_ENGINE_LOADED="defender_engine_loaded"
    DEFENDER_SCAN_STARTED="defender_scan_started"
    DEFENDER_SCAN_COMPLETED="defender_scan_completed"

    DEFENDER_CLOUD_REQUEST="defender_cloud_request"

    DEFENDER_CONFIGURATION_CHANGED="defender_configuration_changed"

    DIRECTORY_CREATED="directory_created"
    DIRECTORY_DELETED="directory_deleted"
    TIMESTAMP_INCONSISTENCY="timestamp_inconsistency"

    POWERSHELL_PIPELINE_EXECUTION = "powershell_pipeline_execution"
