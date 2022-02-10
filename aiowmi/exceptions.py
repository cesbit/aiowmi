from . import const


class NoBindingException(Exception):
    pass


class DcomException(Exception):
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


WbemStopIteration = WbemFalse


class WbemTimeout(WbemException):
    msg = 'WBEM_S_TIMEDOUT'


class WbemNewStyle(WbemException):
    msg = 'WBEM_S_NEW_STYLE'


class WbemPartialResult(WbemException):
    msg = 'WBEM_S_PARTIAL_RESULTS'


class WbemExFailed(WbemException):
    msg = 'WBEM_E_FAILED'


class WbemExNotFound(WbemException):
    msg = 'WBEM_E_NOT_FOUND'


class WbemExAccessDenied(WbemException):
    msg = 'WBEM_E_ACCESS_DENIED'


class WbemExProviderFailure(WbemException):
    msg = 'WBEM_E_PROVIDER_FAILURE'


class WbemExTypeMismatch(WbemException):
    msg = 'WBEM_E_TYPE_MISMATCH'


class WbemExOutOfMemory(WbemException):
    msg = 'WBEM_E_OUT_OF_MEMORY'


class WbemExInvalidContext(WbemException):
    msg = 'WBEM_E_INVALID_CONTEXT'


class WbemExInvalidParameter(WbemException):
    msg = 'WBEM_E_INVALID_PARAMETER'


class WbemExNotAvailable(WbemException):
    msg = 'WBEM_E_NOT_AVAILABLE'


class WbemExCriticalError(WbemException):
    msg = 'WBEM_E_CRITICAL_ERROR'


class WbemExNotSupported(WbemException):
    msg = 'WBEM_E_NOT_SUPPORTED'


class WbemExProviderNotFound(WbemException):
    msg = 'WBEM_E_PROVIDER_NOT_FOUND'


class WbemExInvalidProviderRegistration(WbemException):
    msg = 'WBEM_E_INVALID_PROVIDER_REGISTRATION'


class WbemExProviderLoadFailure(WbemException):
    msg = 'WBEM_E_PROVIDER_LOAD_FAILURE'


class WbemExInitializationFailure(WbemException):
    msg = 'WBEM_E_INITIALIZATION_FAILURE'


class WbemExTransportFailure(WbemException):
    msg = 'WBEM_E_TRANSPORT_FAILURE'


class WbemExInvalidOperation(WbemException):
    msg = 'WBEM_E_INVALID_OPERATION'


class WbemExAlreadyExists(WbemException):
    msg = 'WBEM_E_ALREADY_EXISTS'


class WbemExUnexpected(WbemException):
    msg = 'WBEM_E_UNEXPECTED'


class WbemExIncompleteClass(WbemException):
    msg = 'WBEM_E_INCOMPLETE_CLASS'


class WbemExShuttingDown(WbemException):
    msg = 'WBEM_E_SHUTTING_DOWN'


class WbemExNotimpl(WbemException):
    msg = 'WBEM_E_NOTIMPL'


class WbemExInvalidSuperclass(WbemException):
    msg = 'WBEM_E_INVALID_SUPERCLASS'


class WbemExInvalidNamespace(WbemException):
    msg = 'WBEM_E_INVALID_NAMESPACE'


class WbemExInvalidObject(WbemException):
    msg = 'WBEM_E_INVALID_OBJECT'


class WbemExInvalidClass(WbemException):
    msg = 'WBEM_E_INVALID_CLASS'


class WbemExInvalidQuery(WbemException):
    msg = 'WBEM_E_INVALID_QUERY'


class WbemExInvalidQueryType(WbemException):
    msg = 'WBEM_E_INVALID_QUERY_TYPE'


class WbemExProviderNotCapable(WbemException):
    msg = 'WBEM_E_PROVIDER_NOT_CAPABLE'


class WbemExClassHasChildren(WbemException):
    msg = 'WBEM_E_CLASS_HAS_CHILDREN'


class WbemExClassHasInstances(WbemException):
    msg = 'WBEM_E_CLASS_HAS_INSTANCES'


class WbemExIllegalNull(WbemException):
    msg = 'WBEM_E_ILLEGAL_NULL'


class WbemExInvalidCimType(WbemException):
    msg = 'WBEM_E_INVALID_CIM_TYPE'


class WbemExInvalidMethod(WbemException):
    msg = 'WBEM_E_INVALID_METHOD'


class WbemExInvalidMethodParameters(WbemException):
    msg = 'WBEM_E_INVALID_METHOD_PARAMETERS'


class WbemExInvalidProperty(WbemException):
    msg = 'WBEM_E_INVALID_PROPERTY'


class WbemExCallCancelled(WbemException):
    msg = 'WBEM_E_CALL_CANCELLED'


class WbemExInvalidObjectPath(WbemException):
    msg = 'WBEM_E_INVALID_OBJECT_PATH'


class WbemExOutOfDiskSpace(WbemException):
    msg = 'WBEM_E_OUT_OF_DISK_SPACE'


class WbemExUnsupportedPutExtension(WbemException):
    msg = 'WBEM_E_UNSUPPORTED_PUT_EXTENSION'


class WbemExQuotaViolation(WbemException):
    msg = 'WBEM_E_QUOTA_VIOLATION'


class WbemExServerTooBusy(WbemException):
    msg = 'WBEM_E_SERVER_TOO_BUSY'


class WbemExMethodNotImplemented(WbemException):
    msg = 'WBEM_E_METHOD_NOT_IMPLEMENTED'


class WbemExMethodDisabled(WbemException):
    msg = 'WBEM_E_METHOD_DISABLED'


class WbemExUnpasableQuery(WbemException):
    msg = 'WBEM_E_UNPARSABLE_QUERY'


class WbemExNotEventClass(WbemException):
    msg = 'WBEM_E_NOT_EVENT_CLASS'


class WbemExMissingGroupWithin(WbemException):
    msg = 'WBEM_E_MISSING_GROUP_WITHIN'


class WbemExMissingAggregationList(WbemException):
    msg = 'WBEM_E_MISSING_AGGREGATION_LIST'


class WbemExPropertyNotAnObject(WbemException):
    msg = 'WBEM_E_PROPERTY_NOT_AN_OBJECT'


class WbemExAggregationByObject(WbemException):
    msg = 'WBEM_E_AGGREGATING_BY_OBJECT'


class WbemExBackupRestoreWinmgmtRunning(WbemException):
    msg = 'WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING'


class WbemExQueueOverflow(WbemException):
    msg = 'WBEM_E_QUEUE_OVERFLOW'


class WbemExPrivilegeNotHeld(WbemException):
    msg = 'WBEM_E_PRIVILEGE_NOT_HELD'


class WbemExInvalidOperator(WbemException):
    msg = 'WBEM_E_INVALID_OPERATOR'


class WbemExCannotBeAbstract(WbemException):
    msg = 'WBEM_E_CANNOT_BE_ABSTRACT'


class WbemExAmendedObject(WbemException):
    msg = 'WBEM_E_AMENDED_OBJECT'


class WbemExVetoPut(WbemException):
    msg = 'WBEM_E_VETO_PUT'


class WbemExProviderSuspended(WbemException):
    msg = 'WBEM_E_PROVIDER_SUSPENDED'


class WbemExEnvryptedConnectionRequired(WbemException):
    msg = 'WBEM_E_ENCRYPTED_CONNECTION_REQUIRED'


class WbemExProviderTimedOut(WbemException):
    msg = 'WBEM_E_PROVIDER_TIMED_OUT'


class WbemExNoKey(WbemException):
    msg = 'WBEM_E_NO_KEY'


class WbemExProviderDisabled(WbemException):
    msg = 'WBEM_E_PROVIDER_DISABLED'


class WbemExRegistrationTooBroad(WbemException):
    msg = 'WBEM_E_REGISTRATION_TOO_BROAD'


class WbemExRegistrationTooPrecise(WbemException):
    msg = 'WBEM_E_REGISTRATION_TOO_PRECISE'


_WBEM_EX_LOOKUP = {
    const.WBEM_S_NO_ERROR: WbemNoError,
    const.WBEM_S_FALSE: WbemFalse,
    const.WBEM_S_TIMEDOUT: WbemTimeout,
    const.WBEM_S_NEW_STYLE: WbemNewStyle,
    const.WBEM_S_PARTIAL_RESULTS: WbemPartialResult,
    const.WBEM_E_FAILED: WbemExFailed,
    const.WBEM_E_NOT_FOUND: WbemExNotFound,
    const.WBEM_E_ACCESS_DENIED: WbemExAccessDenied,
    const.WBEM_E_PROVIDER_FAILURE: WbemExProviderFailure,
    const.WBEM_E_TYPE_MISMATCH: WbemExTypeMismatch,
    const.WBEM_E_OUT_OF_MEMORY: WbemExOutOfMemory,
    const.WBEM_E_INVALID_CONTEXT: WbemExInvalidContext,
    const.WBEM_E_INVALID_PARAMETER: WbemExInvalidParameter,
    const.WBEM_E_NOT_AVAILABLE: WbemExNotAvailable,
    const.WBEM_E_CRITICAL_ERROR: WbemExCriticalError,
    const.WBEM_E_NOT_SUPPORTED: WbemExNotSupported,
    const.WBEM_E_PROVIDER_NOT_FOUND: WbemExProviderNotFound,
    const.WBEM_E_INVALID_PROVIDER_REGISTRATION:
        WbemExInvalidProviderRegistration,
    const.WBEM_E_PROVIDER_LOAD_FAILURE: WbemExProviderLoadFailure,
    const.WBEM_E_INITIALIZATION_FAILURE: WbemExInitializationFailure,
    const.WBEM_E_TRANSPORT_FAILURE: WbemExTransportFailure,
    const.WBEM_E_INVALID_OPERATION: WbemExInvalidOperation,
    const.WBEM_E_ALREADY_EXISTS: WbemExAlreadyExists,
    const.WBEM_E_UNEXPECTED: WbemExUnexpected,
    const.WBEM_E_INCOMPLETE_CLASS: WbemExIncompleteClass,
    const.WBEM_E_SHUTTING_DOWN: WbemExShuttingDown,
    const.WBEM_E_NOTIMPL: WbemExNotimpl,
    const.WBEM_E_INVALID_SUPERCLASS: WbemExInvalidSuperclass,
    const.WBEM_E_INVALID_NAMESPACE: WbemExInvalidNamespace,
    const.WBEM_E_INVALID_OBJECT: WbemExInvalidObject,
    const.WBEM_E_INVALID_CLASS: WbemExInvalidClass,
    const.WBEM_E_INVALID_QUERY: WbemExInvalidQuery,
    const.WBEM_E_INVALID_QUERY_TYPE: WbemExInvalidQueryType,
    const.WBEM_E_PROVIDER_NOT_CAPABLE: WbemExProviderNotCapable,
    const.WBEM_E_CLASS_HAS_CHILDREN: WbemExClassHasChildren,
    const.WBEM_E_CLASS_HAS_INSTANCES: WbemExClassHasInstances,
    const.WBEM_E_ILLEGAL_NULL: WbemExIllegalNull,
    const.WBEM_E_INVALID_CIM_TYPE: WbemExInvalidCimType,
    const.WBEM_E_INVALID_METHOD: WbemExInvalidMethod,
    const.WBEM_E_INVALID_METHOD_PARAMETERS: WbemExInvalidMethodParameters,
    const.WBEM_E_INVALID_PROPERTY: WbemExInvalidProperty,
    const.WBEM_E_CALL_CANCELLED: WbemExCallCancelled,
    const.WBEM_E_INVALID_OBJECT_PATH: WbemExInvalidObjectPath,
    const.WBEM_E_OUT_OF_DISK_SPACE: WbemExOutOfDiskSpace,
    const.WBEM_E_UNSUPPORTED_PUT_EXTENSION: WbemExUnsupportedPutExtension,
    const.WBEM_E_QUOTA_VIOLATION: WbemExQuotaViolation,
    const.WBEM_E_SERVER_TOO_BUSY: WbemExServerTooBusy,
    const.WBEM_E_METHOD_NOT_IMPLEMENTED: WbemExMethodNotImplemented,
    const.WBEM_E_METHOD_DISABLED: WbemExMethodDisabled,
    const.WBEM_E_UNPARSABLE_QUERY: WbemExUnpasableQuery,
    const.WBEM_E_NOT_EVENT_CLASS: WbemExNotEventClass,
    const.WBEM_E_MISSING_GROUP_WITHIN: WbemExMissingGroupWithin,
    const.WBEM_E_MISSING_AGGREGATION_LIST: WbemExMissingAggregationList,
    const.WBEM_E_PROPERTY_NOT_AN_OBJECT: WbemExPropertyNotAnObject,
    const.WBEM_E_AGGREGATING_BY_OBJECT: WbemExAggregationByObject,
    const.WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING:
        WbemExBackupRestoreWinmgmtRunning,
    const.WBEM_E_QUEUE_OVERFLOW: WbemExQueueOverflow,
    const.WBEM_E_PRIVILEGE_NOT_HELD: WbemExPrivilegeNotHeld,
    const.WBEM_E_INVALID_OPERATOR: WbemExInvalidOperator,
    const.WBEM_E_CANNOT_BE_ABSTRACT: WbemExCannotBeAbstract,
    const.WBEM_E_AMENDED_OBJECT: WbemExAmendedObject,
    const.WBEM_E_VETO_PUT: WbemExVetoPut,
    const.WBEM_E_PROVIDER_SUSPENDED: WbemExProviderSuspended,
    const.WBEM_E_ENCRYPTED_CONNECTION_REQUIRED:
        WbemExEnvryptedConnectionRequired,
    const.WBEM_E_PROVIDER_TIMED_OUT: WbemExProviderTimedOut,
    const.WBEM_E_NO_KEY: WbemExNoKey,
    const.WBEM_E_PROVIDER_DISABLED: WbemExProviderDisabled,
    const.WBEM_E_REGISTRATION_TOO_BROAD: WbemExRegistrationTooBroad,
    const.WBEM_E_REGISTRATION_TOO_PRECISE: WbemExRegistrationTooPrecise,
}


def wbem_exception(code):
    ex = _WBEM_EX_LOOKUP.get(code, WbemExUnknown)
    return ex(code)
