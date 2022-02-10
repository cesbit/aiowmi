from . import const

class DcomException(Exception):
    pass


class WbemStopIteration(Exception):
    pass


class RpcException(Exception):
    def __init__(self, msg, code):
        msg = f'{msg} ({code})'
        super().__init__(msg)


class WbemException(Exception):
    def __init__(self, code):
        msg = f'{self.msg} ({code})'
        super().__init__(msg)


class WbemExUnknown(WbemException):
    msg = 'WBEM_E_UNKNOWN'


class WbemNoError(WbemException):
    msg = 'WBEM_S_NO_ERROR'


class WbemFalse(WbemException):
    msg = 'WBEM_S_FALSE'


class WbemNewStyle(WbemException): pass
class WbemPartialResult(WbemException): pass
class WbemExFailed(WbemException): pass
class WbemExNotFound(WbemException): pass
class WbemExAccessDenied(WbemException): pass
class WbemExProviderFailure(WbemException): pass
class WbemExTypeMismatch(WbemException): pass
class WbemExOutOfMemory(WbemException): pass
class WbemExInvalidContext(WbemException): pass
class WbemExInvalidParameter(WbemException): pass
class WbemExNotAvailable(WbemException): pass
class WbemExCriticalError(WbemException): pass
class WbemExNotSupported(WbemException): pass
class WbemEx(WbemException): pass
class WbemEx(WbemException): pass
class WbemEx(WbemException): pass
class WbemEx(WbemException): pass
class WbemEx(WbemException): pass


_WBEM_EX_LOOKUP = {
    const.WBEM_S_NO_ERROR: WbemNoError,
    const.WBEM_S_FALSE: WbemFalse,

    0x00000001: 'WBEM_S_FALSE',
    0x00040004: 'WBEM_S_TIMEDOUT',
    0x000400FF: 'WBEM_S_NEW_STYLE',
    0x00040010: 'WBEM_S_PARTIAL_RESULTS',
    0x80041001: 'WBEM_E_FAILED',
    0x80041002: 'WBEM_E_NOT_FOUND',
    0x80041003: 'WBEM_E_ACCESS_DENIED',
    0x80041004: 'WBEM_E_PROVIDER_FAILURE',
    0x80041005: 'WBEM_E_TYPE_MISMATCH',
    0x80041006: 'WBEM_E_OUT_OF_MEMORY',
    0x80041007: 'WBEM_E_INVALID_CONTEXT',
    0x80041008: 'WBEM_E_INVALID_PARAMETER',
    0x80041009: 'WBEM_E_NOT_AVAILABLE',
    0x8004100a: 'WBEM_E_CRITICAL_ERROR',
    0x8004100c: 'WBEM_E_NOT_SUPPORTED',
    0x80041011: 'WBEM_E_PROVIDER_NOT_FOUND',
    0x80041012: 'WBEM_E_INVALID_PROVIDER_REGISTRATION',
    0x80041013: 'WBEM_E_PROVIDER_LOAD_FAILURE',
    0x80041014: 'WBEM_E_INITIALIZATION_FAILURE',
    0x80041015: 'WBEM_E_TRANSPORT_FAILURE',
    0x80041016: 'WBEM_E_INVALID_OPERATION',
    0x80041019: 'WBEM_E_ALREADY_EXISTS',
    0x8004101d: 'WBEM_E_UNEXPECTED',
    0x80041020: 'WBEM_E_INCOMPLETE_CLASS',
    0x80041033: 'WBEM_E_SHUTTING_DOWN',
    0x80004001: 'WBEM_E_NOTIMPL',
    0x8004100D: 'WBEM_E_INVALID_SUPERCLASS',
    0x8004100E: 'WBEM_E_INVALID_NAMESPACE',
    0x8004100F: 'WBEM_E_INVALID_OBJECT',
    0x80041010: 'WBEM_E_INVALID_CLASS',
    0x80041017: 'WBEM_E_INVALID_QUERY',
    0x80041018: 'WBEM_E_INVALID_QUERY_TYPE',
    0x80041024: 'WBEM_E_PROVIDER_NOT_CAPABLE',
    0x80041025: 'WBEM_E_CLASS_HAS_CHILDREN',
    0x80041026: 'WBEM_E_CLASS_HAS_INSTANCES',
    0x80041028: 'WBEM_E_ILLEGAL_NULL',
    0x8004102D: 'WBEM_E_INVALID_CIM_TYPE',
    0x8004102E: 'WBEM_E_INVALID_METHOD',
    0x8004102F: 'WBEM_E_INVALID_METHOD_PARAMETERS',
    0x80041031: 'WBEM_E_INVALID_PROPERTY',
    0x80041032: 'WBEM_E_CALL_CANCELLED',
    0x8004103A: 'WBEM_E_INVALID_OBJECT_PATH',
    0x8004103B: 'WBEM_E_OUT_OF_DISK_SPACE',
    0x8004103D: 'WBEM_E_UNSUPPORTED_PUT_EXTENSION',
    0x8004106c: 'WBEM_E_QUOTA_VIOLATION',
    0x80041045: 'WBEM_E_SERVER_TOO_BUSY',
    0x80041055: 'WBEM_E_METHOD_NOT_IMPLEMENTED',
    0x80041056: 'WBEM_E_METHOD_DISABLED',
    0x80041058: 'WBEM_E_UNPARSABLE_QUERY',
    0x80041059: 'WBEM_E_NOT_EVENT_CLASS',
    0x8004105A: 'WBEM_E_MISSING_GROUP_WITHIN',
    0x8004105B: 'WBEM_E_MISSING_AGGREGATION_LIST',
    0x8004105c: 'WBEM_E_PROPERTY_NOT_AN_OBJECT',
    0x8004105d: 'WBEM_E_AGGREGATING_BY_OBJECT',
    0x80041060: 'WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING',
    0x80041061: 'WBEM_E_QUEUE_OVERFLOW',
    0x80041062: 'WBEM_E_PRIVILEGE_NOT_HELD',
    0x80041063: 'WBEM_E_INVALID_OPERATOR',
    0x80041065: 'WBEM_E_CANNOT_BE_ABSTRACT',
    0x80041066: 'WBEM_E_AMENDED_OBJECT',
    0x8004107A: 'WBEM_E_VETO_PUT',
    0x80041081: 'WBEM_E_PROVIDER_SUSPENDED',
    0x80041087: 'WBEM_E_ENCRYPTED_CONNECTION_REQUIRED',
    0x80041088: 'WBEM_E_PROVIDER_TIMED_OUT',
    0x80041089: 'WBEM_E_NO_KEY',
    0x8004108a: 'WBEM_E_PROVIDER_DISABLED',
    0x80042001: 'WBEM_E_REGISTRATION_TOO_BROAD',
    0x80042002: 'WBEM_E_REGISTRATION_TOO_PRECISE',
}


def wbem_exception(code):
    ex = _WBEM_EX_LOOKUP.get(code, WbemExUnknown)
    return ex(code)
