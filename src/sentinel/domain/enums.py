from enum import StrEnum, auto


class Severity(StrEnum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class IdentityStatus(StrEnum):
    KNOWN = auto()
    UNKNOWN = auto()


class SecurityStatus(StrEnum):
    NORMAL = auto()
    UNUSUAL = auto()
    SUSPICIOUS = auto()
    KNOWN_MALICIOUS = auto()


class PrivacyCategory(StrEnum):
    FIRST_PARTY = auto()
    ANALYTICS = auto()
    ADVERTISING = auto()
    TRACKING = auto()
    TELEMETRY = auto()
    CDN = auto()
    CLOUD_API = auto()
    SOCIAL = auto()
    UNKNOWN = auto()


class ExposureLevel(StrEnum):
    LOOPBACK = auto()
    LOCAL_NETWORK = auto()
    ALL_INTERFACES = auto()


class SocketState(StrEnum):
    LISTEN = auto()
    ESTABLISHED = auto()
    SYN_SENT = auto()
    SYN_RECV = auto()
    FIN_WAIT1 = auto()
    FIN_WAIT2 = auto()
    TIME_WAIT = auto()
    CLOSE = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    CLOSING = auto()
    NONE = auto()
    UNKNOWN = auto()


class EventType(StrEnum):
    PROCESS_STARTED = auto()
    PROCESS_STOPPED = auto()
    PORT_OPENED = auto()
    PORT_CLOSED = auto()
    CONNECTION_OPENED = auto()
    CONNECTION_CLOSED = auto()
    SITE_VISITED = auto()
    COOKIE_CREATED = auto()
    COOKIE_UPDATED = auto()
    COOKIE_REMOVED = auto()
    THIRD_PARTY_REQUEST = auto()
    UNKNOWN_DOMAIN_CONTACTED = auto()
    FINDING_CREATED = auto()
    FINDING_RESOLVED = auto()


class FindingStatus(StrEnum):
    OPEN = auto()
    ACKNOWLEDGED = auto()
    EXPECTED = auto()
    RESOLVED = auto()


class Protocol(StrEnum):
    TCP = auto()
    UDP = auto()
    UNIX = auto()
    UNKNOWN = auto()
