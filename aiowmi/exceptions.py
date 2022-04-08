from . import const
from .rpc import const as rpc_const


class ServerNotOptimized(Exception):
    pass


class NoBindingException(Exception):
    pass


class DcomException(Exception):
    pass


class RpcException(Exception):
    def __init__(self, code):
        msg = f'{self.msg} ({code})'
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


class AccessDenied(RpcException):
    msg = 'ACCESS_DENIED'


class AuthenticationTypeNotRecognized(RpcException):
    msg = 'AUTHENTICATION_TYPE_NOT_RECOGNIZED'


class EptCantPerformOp(RpcException):
    msg = 'EPT_S_CANT_PERFORM_OP'


class RpcInvalidBound(RpcException):
    msg = 'RPC_S_INVALID_BOUND'


class RpcCannotSupport(RpcException):
    msg = 'RPC_S_CANNOT_SUPPORT'


class RpcBadStubData(RpcException):
    msg = 'RPC_X_BAD_STUB_DATA'


class NcaCommFailure(RpcException):
    msg = 'NCA_S_COMM_FAILURE'


class NcaOpRngError(RpcException):
    msg = 'NCA_S_OP_RNG_ERROR'


class NcaUnkIf(RpcException):
    msg = 'NCA_S_UNK_IF'


class NcaWrongBootTime(RpcException):
    msg = 'NCA_S_WRONG_BOOT_TIME'


class NcaYouCrashed(RpcException):
    msg = 'NCA_S_YOU_CRASHED'


class NcaProtoError(RpcException):
    msg = 'NCA_S_PROTO_ERROR'


class NcaOutArgsTooBig(RpcException):
    msg = 'NCA_S_OUT_ARGS_TOO_BIG'


class NcaServerTooBusy(RpcException):
    msg = 'NCA_S_SERVER_TOO_BUSY'


class NcaFaultStringTooLong(RpcException):
    msg = 'NCA_S_FAULT_STRING_TOO_LONG'


class NcaUnsupportedType(RpcException):
    msg = 'NCA_S_UNSUPPORTED_TYPE'


class NcaFaultIntDivByZero(RpcException):
    msg = 'NCA_S_FAULT_INT_DIV_BY_ZERO'


class NcaFaultAddrError(RpcException):
    msg = 'NCA_S_FAULT_ADDR_ERROR'


class NcaFaultFpDivZero(RpcException):
    msg = 'NCA_S_FAULT_FP_DIV_ZERO'


class NcaFaultFpUnderflow(RpcException):
    msg = 'NCA_S_FAULT_FP_UNDERFLOW'


class NcaFaultFpOverflow(RpcException):
    msg = 'NCA_S_FAULT_FP_OVERFLOW'


class NcaFaultInvalidTag(RpcException):
    msg = 'NCA_S_FAULT_INVALID_TAG'


class NcaFaultInvalidBound(RpcException):
    msg = 'NCA_S_FAULT_INVALID_BOUND'


class NcaRpcVersionMismatch(RpcException):
    msg = 'NCA_S_RPC_VERSION_MISMATCH'


class NcaUnspecReject(RpcException):
    msg = 'NCA_S_UNSPEC_REJECT'


class NcaBadActid(RpcException):
    msg = 'NCA_S_BAD_ACTID'


class NcaWhoAreYouFailed(RpcException):
    msg = 'NCA_S_WHO_ARE_YOU_FAILED'


class NcaManagerNotEntered(RpcException):
    msg = 'NCA_S_MANAGER_NOT_ENTERED'


class NcaFaultCancel(RpcException):
    msg = 'NCA_S_FAULT_CANCEL'


class NcaFaultIllInst(RpcException):
    msg = 'NCA_S_FAULT_ILL_INST'


class NcaFaultFpError(RpcException):
    msg = 'NCA_S_FAULT_FP_ERROR'


class NcaFaultIntOverflow(RpcException):
    msg = 'NCA_S_FAULT_INT_OVERFLOW'


class NcaFaultUnspec(RpcException):
    msg = 'NCA_S_FAULT_UNSPEC'


class NcaFaultRemoteCommFailure(RpcException):
    msg = 'NCA_S_FAULT_REMOTE_COMM_FAILURE'


class NcaFaultPipeEmpty(RpcException):
    msg = 'NCA_S_FAULT_PIPE_EMPTY'


class NcaFaultPipeClosed(RpcException):
    msg = 'NCA_S_FAULT_PIPE_CLOSED'


class NcaFaultPipeOrder(RpcException):
    msg = 'NCA_S_FAULT_PIPE_ORDER'


class NcaFaultPipeDiscipline(RpcException):
    msg = 'NCA_S_FAULT_PIPE_DISCIPLINE'


class NcaFaultPipeCommError(RpcException):
    msg = 'NCA_S_FAULT_PIPE_COMM_ERROR'


class NcaFaultPipeMemory(RpcException):
    msg = 'NCA_S_FAULT_PIPE_MEMORY'


class NcaFaultContextMismatch(RpcException):
    msg = 'NCA_S_FAULT_CONTEXT_MISMATCH'


class NcaFaultRemoteNoMemory(RpcException):
    msg = 'NCA_S_FAULT_REMOTE_NO_MEMORY'


class NcaInvalidPresContextId(RpcException):
    msg = 'NCA_S_INVALID_PRES_CONTEXT_ID'


class NcaUnsupportedAuthnLevel(RpcException):
    msg = 'NCA_S_UNSUPPORTED_AUTHN_LEVEL'


class NcaInvalidChecksum(RpcException):
    msg = 'NCA_S_INVALID_CHECKSUM'


class NcaInvalidCrc(RpcException):
    msg = 'NCA_S_INVALID_CRC'


class NcaFaultUserDefined(RpcException):
    msg = 'NCA_S_FAULT_USER_DEFINED'


class NcaFaultTxOpenFailed(RpcException):
    msg = 'NCA_S_FAULT_TX_OPEN_FAILED'


class NcaFaultCodesetConvError(RpcException):
    msg = 'NCA_S_FAULT_CODESET_CONV_ERROR'


class NcaFaultObjectNotFound(RpcException):
    msg = 'NCA_S_FAULT_OBJECT_NOT_FOUND'


class NcaFaultNoClientStub(RpcException):
    msg = 'NCA_S_FAULT_NO_CLIENT_STUB'


class RpcMod(RpcException):
    msg = 'RPC_S_MOD'


class RpcOpRngError(RpcException):
    msg = 'RPC_S_OP_RNG_ERROR'


class RpcCantCreateSocket(RpcException):
    msg = 'RPC_S_CANT_CREATE_SOCKET'


class RpcCantBindSocket(RpcException):
    msg = 'RPC_S_CANT_BIND_SOCKET'


class RpcNotInCall(RpcException):
    msg = 'RPC_S_NOT_IN_CALL'


class RpcNoPort(RpcException):
    msg = 'RPC_S_NO_PORT'


class RpcWrongBootTime(RpcException):
    msg = 'RPC_S_WRONG_BOOT_TIME'


class RpcTooManySockets(RpcException):
    msg = 'RPC_S_TOO_MANY_SOCKETS'


class RpcIllegalRegister(RpcException):
    msg = 'RPC_S_ILLEGAL_REGISTER'


class RpcCantRecv(RpcException):
    msg = 'RPC_S_CANT_RECV'


class RpcBadPkt(RpcException):
    msg = 'RPC_S_BAD_PKT'


class RpcUnboundHandle(RpcException):
    msg = 'RPC_S_UNBOUND_HANDLE'


class RpcAddrInUse(RpcException):
    msg = 'RPC_S_ADDR_IN_USE'


class RpcInArgsTooBig(RpcException):
    msg = 'RPC_S_IN_ARGS_TOO_BIG'


class RpcStringTooLong(RpcException):
    msg = 'RPC_S_STRING_TOO_LONG'


class RpcTooManyObjects(RpcException):
    msg = 'RPC_S_TOO_MANY_OBJECTS'


class RpcBindingHasNoAuth(RpcException):
    msg = 'RPC_S_BINDING_HAS_NO_AUTH'


class RpcUnknownAuthnService(RpcException):
    msg = 'RPC_S_UNKNOWN_AUTHN_SERVICE'


class RpcNoMemory(RpcException):
    msg = 'RPC_S_NO_MEMORY'


class RpcCantNmalloc(RpcException):
    msg = 'RPC_S_CANT_NMALLOC'


class RpcCallFaulted(RpcException):
    msg = 'RPC_S_CALL_FAULTED'


class RpcCallFailed(RpcException):
    msg = 'RPC_S_CALL_FAILED'


class RpcCommFailure(RpcException):
    msg = 'RPC_S_COMM_FAILURE'


class RpcRpcdCommFailure(RpcException):
    msg = 'RPC_S_RPCD_COMM_FAILURE'


class RpcIllegalFamilyRebind(RpcException):
    msg = 'RPC_S_ILLEGAL_FAMILY_REBIND'


class RpcInvalidHandle(RpcException):
    msg = 'RPC_S_INVALID_HANDLE'


class RpcCodingError(RpcException):
    msg = 'RPC_S_CODING_ERROR'


class RpcObjectNotFound(RpcException):
    msg = 'RPC_S_OBJECT_NOT_FOUND'


class RpcCthreadNotFound(RpcException):
    msg = 'RPC_S_CTHREAD_NOT_FOUND'


class RpcInvalidBinding(RpcException):
    msg = 'RPC_S_INVALID_BINDING'


class RpcAlreadyRegistered(RpcException):
    msg = 'RPC_S_ALREADY_REGISTERED'


class RpcEndpointNotFound(RpcException):
    msg = 'RPC_S_ENDPOINT_NOT_FOUND'


class RpcInvalidRpcProtseq(RpcException):
    msg = 'RPC_S_INVALID_RPC_PROTSEQ'


class RpcDescNotRegistered(RpcException):
    msg = 'RPC_S_DESC_NOT_REGISTERED'


class RpcAlreadyListening(RpcException):
    msg = 'RPC_S_ALREADY_LISTENING'


class RpcNoProtseqs(RpcException):
    msg = 'RPC_S_NO_PROTSEQS'


class RpcNoProtseqsRegistered(RpcException):
    msg = 'RPC_S_NO_PROTSEQS_REGISTERED'


class RpcNoBindings(RpcException):
    msg = 'RPC_S_NO_BINDINGS'


class RpcMaxDescsExceeded(RpcException):
    msg = 'RPC_S_MAX_DESCS_EXCEEDED'


class RpcNoInterfaces(RpcException):
    msg = 'RPC_S_NO_INTERFACES'


class RpcInvalidTimeout(RpcException):
    msg = 'RPC_S_INVALID_TIMEOUT'


class RpcCantInqSocket(RpcException):
    msg = 'RPC_S_CANT_INQ_SOCKET'


class RpcInvalidNafId(RpcException):
    msg = 'RPC_S_INVALID_NAF_ID'


class RpcInvalNetAddr(RpcException):
    msg = 'RPC_S_INVAL_NET_ADDR'


class RpcUnknownIf(RpcException):
    msg = 'RPC_S_UNKNOWN_IF'


class RpcUnsupportedType(RpcException):
    msg = 'RPC_S_UNSUPPORTED_TYPE'


class RpcInvalidCallOpt(RpcException):
    msg = 'RPC_S_INVALID_CALL_OPT'


class RpcNoFault(RpcException):
    msg = 'RPC_S_NO_FAULT'


class RpcCancelTimeout(RpcException):
    msg = 'RPC_S_CANCEL_TIMEOUT'


class RpcCallCancelled(RpcException):
    msg = 'RPC_S_CALL_CANCELLED'


class RpcInvalidCallHandle(RpcException):
    msg = 'RPC_S_INVALID_CALL_HANDLE'


class RpcCannotAllocAssoc(RpcException):
    msg = 'RPC_S_CANNOT_ALLOC_ASSOC'


class RpcCannotConnect(RpcException):
    msg = 'RPC_S_CANNOT_CONNECT'


class RpcConnectionAborted(RpcException):
    msg = 'RPC_S_CONNECTION_ABORTED'


class RpcConnectionClosed(RpcException):
    msg = 'RPC_S_CONNECTION_CLOSED'


class RpcCannotAccept(RpcException):
    msg = 'RPC_S_CANNOT_ACCEPT'


class RpcAssocGrpNotFound(RpcException):
    msg = 'RPC_S_ASSOC_GRP_NOT_FOUND'


class RpcStubInterfaceError(RpcException):
    msg = 'RPC_S_STUB_INTERFACE_ERROR'


class RpcInvalidObject(RpcException):
    msg = 'RPC_S_INVALID_OBJECT'


class RpcInvalidType(RpcException):
    msg = 'RPC_S_INVALID_TYPE'


class RpcInvalidIfOpnum(RpcException):
    msg = 'RPC_S_INVALID_IF_OPNUM'


class RpcDifferentServerInstance(RpcException):
    msg = 'RPC_S_DIFFERENT_SERVER_INSTANCE'


class RpcProtocolError(RpcException):
    msg = 'RPC_S_PROTOCOL_ERROR'


class RpcCantRecvmsg(RpcException):
    msg = 'RPC_S_CANT_RECVMSG'


class RpcInvalidStringBinding(RpcException):
    msg = 'RPC_S_INVALID_STRING_BINDING'


class RpcConnectTimedOut(RpcException):
    msg = 'RPC_S_CONNECT_TIMED_OUT'


class RpcConnectRejected(RpcException):
    msg = 'RPC_S_CONNECT_REJECTED'


class RpcNetworkUnreachable(RpcException):
    msg = 'RPC_S_NETWORK_UNREACHABLE'


class RpcConnectNoResources(RpcException):
    msg = 'RPC_S_CONNECT_NO_RESOURCES'


class RpcRemNetworkShutdown(RpcException):
    msg = 'RPC_S_REM_NETWORK_SHUTDOWN'


class RpcTooManyRemConnects(RpcException):
    msg = 'RPC_S_TOO_MANY_REM_CONNECTS'


class RpcNoRemEndpoint(RpcException):
    msg = 'RPC_S_NO_REM_ENDPOINT'


class RpcRemHostDown(RpcException):
    msg = 'RPC_S_REM_HOST_DOWN'


class RpcHostUnreachable(RpcException):
    msg = 'RPC_S_HOST_UNREACHABLE'


class RpcAccessControlInfoInv(RpcException):
    msg = 'RPC_S_ACCESS_CONTROL_INFO_INV'


class RpcLocConnectAborted(RpcException):
    msg = 'RPC_S_LOC_CONNECT_ABORTED'


class RpcConnectClosedByRem(RpcException):
    msg = 'RPC_S_CONNECT_CLOSED_BY_REM'


class RpcRemHostCrashed(RpcException):
    msg = 'RPC_S_REM_HOST_CRASHED'


class RpcInvalidEndpointFormat(RpcException):
    msg = 'RPC_S_INVALID_ENDPOINT_FORMAT'


class RpcUnknownStatusCode(RpcException):
    msg = 'RPC_S_UNKNOWN_STATUS_CODE'


class RpcUnknownMgrType(RpcException):
    msg = 'RPC_S_UNKNOWN_MGR_TYPE'


class RpcAssocCreationFailed(RpcException):
    msg = 'RPC_S_ASSOC_CREATION_FAILED'


class RpcAssocGrpMaxExceeded(RpcException):
    msg = 'RPC_S_ASSOC_GRP_MAX_EXCEEDED'


class RpcAssocGrpAllocFailed(RpcException):
    msg = 'RPC_S_ASSOC_GRP_ALLOC_FAILED'


class RpcSmInvalidState(RpcException):
    msg = 'RPC_S_SM_INVALID_STATE'


class RpcAssocReqRejected(RpcException):
    msg = 'RPC_S_ASSOC_REQ_REJECTED'


class RpcAssocShutdown(RpcException):
    msg = 'RPC_S_ASSOC_SHUTDOWN'


class RpcTsyntaxesUnsupported(RpcException):
    msg = 'RPC_S_TSYNTAXES_UNSUPPORTED'


class RpcContextIdNotFound(RpcException):
    msg = 'RPC_S_CONTEXT_ID_NOT_FOUND'


class RpcCantListenSocket(RpcException):
    msg = 'RPC_S_CANT_LISTEN_SOCKET'


class RpcNoAddrs(RpcException):
    msg = 'RPC_S_NO_ADDRS'


class RpcCantGetpeername(RpcException):
    msg = 'RPC_S_CANT_GETPEERNAME'


class RpcCantGetIfId(RpcException):
    msg = 'RPC_S_CANT_GET_IF_ID'


class RpcProtseqNotSupported(RpcException):
    msg = 'RPC_S_PROTSEQ_NOT_SUPPORTED'


class RpcCallOrphaned(RpcException):
    msg = 'RPC_S_CALL_ORPHANED'


class RpcWhoAreYouFailed(RpcException):
    msg = 'RPC_S_WHO_ARE_YOU_FAILED'


class RpcUnknownReject(RpcException):
    msg = 'RPC_S_UNKNOWN_REJECT'


class RpcTypeAlreadyRegistered(RpcException):
    msg = 'RPC_S_TYPE_ALREADY_REGISTERED'


class RpcStopListeningDisabled(RpcException):
    msg = 'RPC_S_STOP_LISTENING_DISABLED'


class RpcInvalidArg(RpcException):
    msg = 'RPC_S_INVALID_ARG'


class RpcNotSupported(RpcException):
    msg = 'RPC_S_NOT_SUPPORTED'


class RpcWrongKindOfBinding(RpcException):
    msg = 'RPC_S_WRONG_KIND_OF_BINDING'


class RpcAuthnAuthzMismatch(RpcException):
    msg = 'RPC_S_AUTHN_AUTHZ_MISMATCH'


class RpcCallQueued(RpcException):
    msg = 'RPC_S_CALL_QUEUED'


class RpcCannotSetNodelay(RpcException):
    msg = 'RPC_S_CANNOT_SET_NODELAY'


class RpcNotRpcTower(RpcException):
    msg = 'RPC_S_NOT_RPC_TOWER'


class RpcInvalidRpcProtid(RpcException):
    msg = 'RPC_S_INVALID_RPC_PROTID'


class RpcInvalidRpcFloor(RpcException):
    msg = 'RPC_S_INVALID_RPC_FLOOR'


class RpcCallTimeout(RpcException):
    msg = 'RPC_S_CALL_TIMEOUT'


class RpcMgmtOpDisallowed(RpcException):
    msg = 'RPC_S_MGMT_OP_DISALLOWED'


class RpcUnknown(RpcException):
    msg = 'unknown rpc exception'


class RpcAccessDenied(RpcException):
    msg = 'RPC_S_ACCESS_DENIED'


class RpcManagerNotEntered(RpcException):
    msg = 'RPC_S_MANAGER_NOT_ENTERED'


class RpcCallsTooLargeForWkEp(RpcException):
    msg = 'RPC_S_CALLS_TOO_LARGE_FOR_WK_EP'


class RpcServerTooBusy(RpcException):
    msg = 'RPC_S_SERVER_TOO_BUSY'


class RpcProtVersionMismatch(RpcException):
    msg = 'RPC_S_PROT_VERSION_MISMATCH'


class RpcRpcProtVersionMismatch(RpcException):
    msg = 'RPC_S_RPC_PROT_VERSION_MISMATCH'


class RpcSsNoImportCursor(RpcException):
    msg = 'RPC_S_SS_NO_IMPORT_CURSOR'


class RpcFaultAddrError(RpcException):
    msg = 'RPC_S_FAULT_ADDR_ERROR'


class RpcFaultContextMismatch(RpcException):
    msg = 'RPC_S_FAULT_CONTEXT_MISMATCH'


class RpcFaultFpDivByZero(RpcException):
    msg = 'RPC_S_FAULT_FP_DIV_BY_ZERO'


class RpcFaultFpError(RpcException):
    msg = 'RPC_S_FAULT_FP_ERROR'


class RpcFaultFpOverflow(RpcException):
    msg = 'RPC_S_FAULT_FP_OVERFLOW'


class RpcFaultFpUnderflow(RpcException):
    msg = 'RPC_S_FAULT_FP_UNDERFLOW'


class RpcFaultIllInst(RpcException):
    msg = 'RPC_S_FAULT_ILL_INST'


class RpcFaultIntDivByZero(RpcException):
    msg = 'RPC_S_FAULT_INT_DIV_BY_ZERO'


class RpcFaultIntOverflow(RpcException):
    msg = 'RPC_S_FAULT_INT_OVERFLOW'


class RpcFaultInvalidBound(RpcException):
    msg = 'RPC_S_FAULT_INVALID_BOUND'


class RpcFaultInvalidTag(RpcException):
    msg = 'RPC_S_FAULT_INVALID_TAG'


class RpcFaultPipeClosed(RpcException):
    msg = 'RPC_S_FAULT_PIPE_CLOSED'


class RpcFaultPipeCommError(RpcException):
    msg = 'RPC_S_FAULT_PIPE_COMM_ERROR'


class RpcFaultPipeDiscipline(RpcException):
    msg = 'RPC_S_FAULT_PIPE_DISCIPLINE'


class RpcFaultPipeEmpty(RpcException):
    msg = 'RPC_S_FAULT_PIPE_EMPTY'


class RpcFaultPipeMemory(RpcException):
    msg = 'RPC_S_FAULT_PIPE_MEMORY'


class RpcFaultPipeOrder(RpcException):
    msg = 'RPC_S_FAULT_PIPE_ORDER'


class RpcFaultRemoteCommFailure(RpcException):
    msg = 'RPC_S_FAULT_REMOTE_COMM_FAILURE'


class RpcFaultRemoteNoMemory(RpcException):
    msg = 'RPC_S_FAULT_REMOTE_NO_MEMORY'


class RpcFaultUnspec(RpcException):
    msg = 'RPC_S_FAULT_UNSPEC'


class UuidBadVersion(RpcException):
    msg = 'UUID_S_BAD_VERSION'


class UuidSocketFailure(RpcException):
    msg = 'UUID_S_SOCKET_FAILURE'


class UuidGetconfFailure(RpcException):
    msg = 'UUID_S_GETCONF_FAILURE'


class UuidNoAddress(RpcException):
    msg = 'UUID_S_NO_ADDRESS'


class UuidOverrun(RpcException):
    msg = 'UUID_S_OVERRUN'


class UuidInternalError(RpcException):
    msg = 'UUID_S_INTERNAL_ERROR'


class UuidCodingError(RpcException):
    msg = 'UUID_S_CODING_ERROR'


class UuidInvalidStringUuid(RpcException):
    msg = 'UUID_S_INVALID_STRING_UUID'


class UuidNoMemory(RpcException):
    msg = 'UUID_S_NO_MEMORY'


class RpcNoMoreEntries(RpcException):
    msg = 'RPC_S_NO_MORE_ENTRIES'


class RpcUnknownNsError(RpcException):
    msg = 'RPC_S_UNKNOWN_NS_ERROR'


class RpcNameServiceUnavailable(RpcException):
    msg = 'RPC_S_NAME_SERVICE_UNAVAILABLE'


class RpcIncompleteName(RpcException):
    msg = 'RPC_S_INCOMPLETE_NAME'


class RpcGroupNotFound(RpcException):
    msg = 'RPC_S_GROUP_NOT_FOUND'


class RpcInvalidNameSyntax(RpcException):
    msg = 'RPC_S_INVALID_NAME_SYNTAX'


class RpcNoMoreMembers(RpcException):
    msg = 'RPC_S_NO_MORE_MEMBERS'


class RpcNoMoreInterfaces(RpcException):
    msg = 'RPC_S_NO_MORE_INTERFACES'


class RpcInvalidNameService(RpcException):
    msg = 'RPC_S_INVALID_NAME_SERVICE'


class RpcNoNameMapping(RpcException):
    msg = 'RPC_S_NO_NAME_MAPPING'


class RpcProfileNotFound(RpcException):
    msg = 'RPC_S_PROFILE_NOT_FOUND'


class RpcNotFound(RpcException):
    msg = 'RPC_S_NOT_FOUND'


class RpcNoUpdates(RpcException):
    msg = 'RPC_S_NO_UPDATES'


class RpcUpdateFailed(RpcException):
    msg = 'RPC_S_UPDATE_FAILED'


class RpcNoMatchExported(RpcException):
    msg = 'RPC_S_NO_MATCH_EXPORTED'


class RpcEntryNotFound(RpcException):
    msg = 'RPC_S_ENTRY_NOT_FOUND'


class RpcInvalidInquiryContext(RpcException):
    msg = 'RPC_S_INVALID_INQUIRY_CONTEXT'


class RpcInterfaceNotFound(RpcException):
    msg = 'RPC_S_INTERFACE_NOT_FOUND'


class RpcGroupMemberNotFound(RpcException):
    msg = 'RPC_S_GROUP_MEMBER_NOT_FOUND'


class RpcEntryAlreadyExists(RpcException):
    msg = 'RPC_S_ENTRY_ALREADY_EXISTS'


class RpcNsinitFailure(RpcException):
    msg = 'RPC_S_NSINIT_FAILURE'


class RpcUnsupportedNameSyntax(RpcException):
    msg = 'RPC_S_UNSUPPORTED_NAME_SYNTAX'


class RpcNoMoreElements(RpcException):
    msg = 'RPC_S_NO_MORE_ELEMENTS'


class RpcNoNsPermission(RpcException):
    msg = 'RPC_S_NO_NS_PERMISSION'


class RpcInvalidInquiryType(RpcException):
    msg = 'RPC_S_INVALID_INQUIRY_TYPE'


class RpcProfileElementNotFound(RpcException):
    msg = 'RPC_S_PROFILE_ELEMENT_NOT_FOUND'


class RpcProfileElementReplaced(RpcException):
    msg = 'RPC_S_PROFILE_ELEMENT_REPLACED'


class RpcImportAlreadyDone(RpcException):
    msg = 'RPC_S_IMPORT_ALREADY_DONE'


class RpcDatabaseBusy(RpcException):
    msg = 'RPC_S_DATABASE_BUSY'


class RpcInvalidImportContext(RpcException):
    msg = 'RPC_S_INVALID_IMPORT_CONTEXT'


class RpcUuidSetNotFound(RpcException):
    msg = 'RPC_S_UUID_SET_NOT_FOUND'


class RpcUuidMemberNotFound(RpcException):
    msg = 'RPC_S_UUID_MEMBER_NOT_FOUND'


class RpcNoInterfacesExported(RpcException):
    msg = 'RPC_S_NO_INTERFACES_EXPORTED'


class RpcTowerSetNotFound(RpcException):
    msg = 'RPC_S_TOWER_SET_NOT_FOUND'


class RpcTowerMemberNotFound(RpcException):
    msg = 'RPC_S_TOWER_MEMBER_NOT_FOUND'


class RpcObjUuidNotFound(RpcException):
    msg = 'RPC_S_OBJ_UUID_NOT_FOUND'


class RpcNoMoreBindings(RpcException):
    msg = 'RPC_S_NO_MORE_BINDINGS'


class RpcInvalidPriority(RpcException):
    msg = 'RPC_S_INVALID_PRIORITY'


class RpcNotRpcEntry(RpcException):
    msg = 'RPC_S_NOT_RPC_ENTRY'


class RpcInvalidLookupContext(RpcException):
    msg = 'RPC_S_INVALID_LOOKUP_CONTEXT'


class RpcBindingVectorFull(RpcException):
    msg = 'RPC_S_BINDING_VECTOR_FULL'


class RpcCycleDetected(RpcException):
    msg = 'RPC_S_CYCLE_DETECTED'


class RpcNothingToExport(RpcException):
    msg = 'RPC_S_NOTHING_TO_EXPORT'


class RpcNothingToUnexport(RpcException):
    msg = 'RPC_S_NOTHING_TO_UNEXPORT'


class RpcInvalidVersOption(RpcException):
    msg = 'RPC_S_INVALID_VERS_OPTION'


class RpcNoRpcData(RpcException):
    msg = 'RPC_S_NO_RPC_DATA'


class RpcMbrPicked(RpcException):
    msg = 'RPC_S_MBR_PICKED'


class RpcNotAllObjsUnexported(RpcException):
    msg = 'RPC_S_NOT_ALL_OBJS_UNEXPORTED'


class RpcNoEntryName(RpcException):
    msg = 'RPC_S_NO_ENTRY_NAME'


class RpcPriorityGroupDone(RpcException):
    msg = 'RPC_S_PRIORITY_GROUP_DONE'


class RpcPartialResults(RpcException):
    msg = 'RPC_S_PARTIAL_RESULTS'


class RpcNoEnvSetup(RpcException):
    msg = 'RPC_S_NO_ENV_SETUP'


class TwrUnknownSa(RpcException):
    msg = 'TWR_S_UNKNOWN_SA'


class TwrUnknownTower(RpcException):
    msg = 'TWR_S_UNKNOWN_TOWER'


class TwrNotImplemented(RpcException):
    msg = 'TWR_S_NOT_IMPLEMENTED'


class RpcMaxCallsTooSmall(RpcException):
    msg = 'RPC_S_MAX_CALLS_TOO_SMALL'


class RpcCthreadCreateFailed(RpcException):
    msg = 'RPC_S_CTHREAD_CREATE_FAILED'


class RpcCthreadPoolExists(RpcException):
    msg = 'RPC_S_CTHREAD_POOL_EXISTS'


class RpcCthreadNoSuchPool(RpcException):
    msg = 'RPC_S_CTHREAD_NO_SUCH_POOL'


class RpcCthreadInvokeDisabled(RpcException):
    msg = 'RPC_S_CTHREAD_INVOKE_DISABLED'


class EptCantPerformOp(RpcException):
    msg = 'EPT_S_CANT_PERFORM_OP'


class EptNoMemory(RpcException):
    msg = 'EPT_S_NO_MEMORY'


class EptDatabaseInvalid(RpcException):
    msg = 'EPT_S_DATABASE_INVALID'


class EptCantCreate(RpcException):
    msg = 'EPT_S_CANT_CREATE'


class EptCantAccess(RpcException):
    msg = 'EPT_S_CANT_ACCESS'


class EptDatabaseAlreadyOpen(RpcException):
    msg = 'EPT_S_DATABASE_ALREADY_OPEN'


class EptInvalidEntry(RpcException):
    msg = 'EPT_S_INVALID_ENTRY'


class EptUpdateFailed(RpcException):
    msg = 'EPT_S_UPDATE_FAILED'


class EptInvalidContext(RpcException):
    msg = 'EPT_S_INVALID_CONTEXT'


class EptNotRegistered(RpcException):
    msg = 'EPT_S_NOT_REGISTERED'


class EptServerUnavailable(RpcException):
    msg = 'EPT_S_SERVER_UNAVAILABLE'


class RpcUnderspecifiedName(RpcException):
    msg = 'RPC_S_UNDERSPECIFIED_NAME'


class RpcInvalidNsHandle(RpcException):
    msg = 'RPC_S_INVALID_NS_HANDLE'


class RpcUnknownError(RpcException):
    msg = 'RPC_S_UNKNOWN_ERROR'


class RpcSsCharTransOpenFail(RpcException):
    msg = 'RPC_S_SS_CHAR_TRANS_OPEN_FAIL'


class RpcSsCharTransShortFile(RpcException):
    msg = 'RPC_S_SS_CHAR_TRANS_SHORT_FILE'


class RpcSsContextDamaged(RpcException):
    msg = 'RPC_S_SS_CONTEXT_DAMAGED'


class RpcSsInNullContext(RpcException):
    msg = 'RPC_S_SS_IN_NULL_CONTEXT'


class RpcSocketFailure(RpcException):
    msg = 'RPC_S_SOCKET_FAILURE'


class RpcUnsupportedProtectLevel(RpcException):
    msg = 'RPC_S_UNSUPPORTED_PROTECT_LEVEL'


class RpcInvalidChecksum(RpcException):
    msg = 'RPC_S_INVALID_CHECKSUM'


class RpcInvalidCredentials(RpcException):
    msg = 'RPC_S_INVALID_CREDENTIALS'


class RpcCredentialsTooLarge(RpcException):
    msg = 'RPC_S_CREDENTIALS_TOO_LARGE'


class RpcCallIdNotFound(RpcException):
    msg = 'RPC_S_CALL_ID_NOT_FOUND'


class RpcKeyIdNotFound(RpcException):
    msg = 'RPC_S_KEY_ID_NOT_FOUND'


class RpcAuthBadIntegrity(RpcException):
    msg = 'RPC_S_AUTH_BAD_INTEGRITY'


class RpcAuthTktExpired(RpcException):
    msg = 'RPC_S_AUTH_TKT_EXPIRED'


class RpcAuthTktNyv(RpcException):
    msg = 'RPC_S_AUTH_TKT_NYV'


class RpcAuthRepeat(RpcException):
    msg = 'RPC_S_AUTH_REPEAT'


class RpcAuthNotUs(RpcException):
    msg = 'RPC_S_AUTH_NOT_US'


class RpcAuthBadmatch(RpcException):
    msg = 'RPC_S_AUTH_BADMATCH'


class RpcAuthSkew(RpcException):
    msg = 'RPC_S_AUTH_SKEW'


class RpcAuthBadaddr(RpcException):
    msg = 'RPC_S_AUTH_BADADDR'


class RpcAuthBadversion(RpcException):
    msg = 'RPC_S_AUTH_BADVERSION'


class RpcAuthMsgType(RpcException):
    msg = 'RPC_S_AUTH_MSG_TYPE'


class RpcAuthModified(RpcException):
    msg = 'RPC_S_AUTH_MODIFIED'


class RpcAuthBadorder(RpcException):
    msg = 'RPC_S_AUTH_BADORDER'


class RpcAuthBadkeyver(RpcException):
    msg = 'RPC_S_AUTH_BADKEYVER'


class RpcAuthNokey(RpcException):
    msg = 'RPC_S_AUTH_NOKEY'


class RpcAuthMutFail(RpcException):
    msg = 'RPC_S_AUTH_MUT_FAIL'


class RpcAuthBaddirection(RpcException):
    msg = 'RPC_S_AUTH_BADDIRECTION'


class RpcAuthMethod(RpcException):
    msg = 'RPC_S_AUTH_METHOD'


class RpcAuthBadseq(RpcException):
    msg = 'RPC_S_AUTH_BADSEQ'


class RpcAuthInappCksum(RpcException):
    msg = 'RPC_S_AUTH_INAPP_CKSUM'


class RpcAuthFieldToolong(RpcException):
    msg = 'RPC_S_AUTH_FIELD_TOOLONG'


class RpcInvalidCrc(RpcException):
    msg = 'RPC_S_INVALID_CRC'


class RpcBindingIncomplete(RpcException):
    msg = 'RPC_S_BINDING_INCOMPLETE'


class RpcKeyFuncNotAllowed(RpcException):
    msg = 'RPC_S_KEY_FUNC_NOT_ALLOWED'


class RpcUnknownStubRtlIfVers(RpcException):
    msg = 'RPC_S_UNKNOWN_STUB_RTL_IF_VERS'


class RpcUnknownIfspecVers(RpcException):
    msg = 'RPC_S_UNKNOWN_IFSPEC_VERS'


class RpcProtoUnsuppByAuth(RpcException):
    msg = 'RPC_S_PROTO_UNSUPP_BY_AUTH'


class RpcAuthnChallengeMalformed(RpcException):
    msg = 'RPC_S_AUTHN_CHALLENGE_MALFORMED'


class RpcProtectLevelMismatch(RpcException):
    msg = 'RPC_S_PROTECT_LEVEL_MISMATCH'


class RpcNoMepv(RpcException):
    msg = 'RPC_S_NO_MEPV'


class RpcStubProtocolError(RpcException):
    msg = 'RPC_S_STUB_PROTOCOL_ERROR'


class RpcClassVersionMismatch(RpcException):
    msg = 'RPC_S_CLASS_VERSION_MISMATCH'


class RpcHelperNotRunning(RpcException):
    msg = 'RPC_S_HELPER_NOT_RUNNING'


class RpcHelperShortRead(RpcException):
    msg = 'RPC_S_HELPER_SHORT_READ'


class RpcHelperCatatonic(RpcException):
    msg = 'RPC_S_HELPER_CATATONIC'


class RpcHelperAborted(RpcException):
    msg = 'RPC_S_HELPER_ABORTED'


class RpcNotInKernel(RpcException):
    msg = 'RPC_S_NOT_IN_KERNEL'


class RpcHelperWrongUser(RpcException):
    msg = 'RPC_S_HELPER_WRONG_USER'


class RpcHelperOverflow(RpcException):
    msg = 'RPC_S_HELPER_OVERFLOW'


class RpcDgNeedWayAuth(RpcException):
    msg = 'RPC_S_DG_NEED_WAY_AUTH'


class RpcUnsupportedAuthSubtype(RpcException):
    msg = 'RPC_S_UNSUPPORTED_AUTH_SUBTYPE'


class RpcWrongPickleType(RpcException):
    msg = 'RPC_S_WRONG_PICKLE_TYPE'


class RpcNotListening(RpcException):
    msg = 'RPC_S_NOT_LISTENING'


class RpcSsBadBuffer(RpcException):
    msg = 'RPC_S_SS_BAD_BUFFER'


class RpcSsBadEsAction(RpcException):
    msg = 'RPC_S_SS_BAD_ES_ACTION'


class RpcSsWrongEsVersion(RpcException):
    msg = 'RPC_S_SS_WRONG_ES_VERSION'


class RpcFaultUserDefined(RpcException):
    msg = 'RPC_S_FAULT_USER_DEFINED'


class RpcSsIncompatibleCodesets(RpcException):
    msg = 'RPC_S_SS_INCOMPATIBLE_CODESETS'


class RpcTxNotInTransaction(RpcException):
    msg = 'RPC_S_TX_NOT_IN_TRANSACTION'


class RpcTxOpenFailed(RpcException):
    msg = 'RPC_S_TX_OPEN_FAILED'


class RpcPartialCredentials(RpcException):
    msg = 'RPC_S_PARTIAL_CREDENTIALS'


class RpcSsInvalidCodesetTag(RpcException):
    msg = 'RPC_S_SS_INVALID_CODESET_TAG'


class RpcMgmtBadType(RpcException):
    msg = 'RPC_S_MGMT_BAD_TYPE'


class RpcSsInvalidCharInput(RpcException):
    msg = 'RPC_S_SS_INVALID_CHAR_INPUT'


class RpcSsShortConvBuffer(RpcException):
    msg = 'RPC_S_SS_SHORT_CONV_BUFFER'


class RpcSsIconvError(RpcException):
    msg = 'RPC_S_SS_ICONV_ERROR'


class RpcSsNoCompatCodeset(RpcException):
    msg = 'RPC_S_SS_NO_COMPAT_CODESET'


class RpcSsNoCompatCharsets(RpcException):
    msg = 'RPC_S_SS_NO_COMPAT_CHARSETS'


class DceCsOk(RpcException):
    msg = 'DCE_CS_C_OK'


class DceCsUnknown(RpcException):
    msg = 'DCE_CS_C_UNKNOWN'


class DceCsNotfound(RpcException):
    msg = 'DCE_CS_C_NOTFOUND'


class DceCsCannotOpenFile(RpcException):
    msg = 'DCE_CS_C_CANNOT_OPEN_FILE'


class DceCsCannotReadFile(RpcException):
    msg = 'DCE_CS_C_CANNOT_READ_FILE'


class DceCsCannotAllocateMemory(RpcException):
    msg = 'DCE_CS_C_CANNOT_ALLOCATE_MEMORY'


class RpcSsCleanupFailed(RpcException):
    msg = 'RPC_S_SS_CLEANUP_FAILED'


class RpcSvcDescGeneral(RpcException):
    msg = 'RPC_SVC_DESC_GENERAL'


class RpcSvcDescMutex(RpcException):
    msg = 'RPC_SVC_DESC_MUTEX'


class RpcSvcDescXmit(RpcException):
    msg = 'RPC_SVC_DESC_XMIT'


class RpcSvcDescRecv(RpcException):
    msg = 'RPC_SVC_DESC_RECV'


class RpcSvcDescDgState(RpcException):
    msg = 'RPC_SVC_DESC_DG_STATE'


class RpcSvcDescCancel(RpcException):
    msg = 'RPC_SVC_DESC_CANCEL'


class RpcSvcDescOrphan(RpcException):
    msg = 'RPC_SVC_DESC_ORPHAN'


class RpcSvcDescCnState(RpcException):
    msg = 'RPC_SVC_DESC_CN_STATE'


class RpcSvcDescCnPkt(RpcException):
    msg = 'RPC_SVC_DESC_CN_PKT'


class RpcSvcDescPktQuotas(RpcException):
    msg = 'RPC_SVC_DESC_PKT_QUOTAS'


class RpcSvcDescAuth(RpcException):
    msg = 'RPC_SVC_DESC_AUTH'


class RpcSvcDescSource(RpcException):
    msg = 'RPC_SVC_DESC_SOURCE'


class RpcSvcDescStats(RpcException):
    msg = 'RPC_SVC_DESC_STATS'


class RpcSvcDescMem(RpcException):
    msg = 'RPC_SVC_DESC_MEM'


class RpcSvcDescMemType(RpcException):
    msg = 'RPC_SVC_DESC_MEM_TYPE'


class RpcSvcDescDgPktlog(RpcException):
    msg = 'RPC_SVC_DESC_DG_PKTLOG'


class RpcSvcDescThreadId(RpcException):
    msg = 'RPC_SVC_DESC_THREAD_ID'


class RpcSvcDescTimestamp(RpcException):
    msg = 'RPC_SVC_DESC_TIMESTAMP'


class RpcSvcDescCnErrors(RpcException):
    msg = 'RPC_SVC_DESC_CN_ERRORS'


class RpcSvcDescConvThread(RpcException):
    msg = 'RPC_SVC_DESC_CONV_THREAD'


class RpcSvcDescPid(RpcException):
    msg = 'RPC_SVC_DESC_PID'


class RpcSvcDescAtfork(RpcException):
    msg = 'RPC_SVC_DESC_ATFORK'


class RpcSvcDescCmaThread(RpcException):
    msg = 'RPC_SVC_DESC_CMA_THREAD'


class RpcSvcDescInherit(RpcException):
    msg = 'RPC_SVC_DESC_INHERIT'


class RpcSvcDescDgSockets(RpcException):
    msg = 'RPC_SVC_DESC_DG_SOCKETS'


class RpcSvcDescTimer(RpcException):
    msg = 'RPC_SVC_DESC_TIMER'


class RpcSvcDescThreads(RpcException):
    msg = 'RPC_SVC_DESC_THREADS'


class RpcSvcDescServerCall(RpcException):
    msg = 'RPC_SVC_DESC_SERVER_CALL'


class RpcSvcDescNsi(RpcException):
    msg = 'RPC_SVC_DESC_NSI'


class RpcSvcDescDgPkt(RpcException):
    msg = 'RPC_SVC_DESC_DG_PKT'


class RpcCnIllStateTransSa(RpcException):
    msg = 'RPC_M_CN_ILL_STATE_TRANS_SA'


class RpcCnIllStateTransCa(RpcException):
    msg = 'RPC_M_CN_ILL_STATE_TRANS_CA'


class RpcCnIllStateTransSg(RpcException):
    msg = 'RPC_M_CN_ILL_STATE_TRANS_SG'


class RpcCnIllStateTransCg(RpcException):
    msg = 'RPC_M_CN_ILL_STATE_TRANS_CG'


class RpcCnIllStateTransSr(RpcException):
    msg = 'RPC_M_CN_ILL_STATE_TRANS_SR'


class RpcCnIllStateTransCr(RpcException):
    msg = 'RPC_M_CN_ILL_STATE_TRANS_CR'


class RpcBadPktType(RpcException):
    msg = 'RPC_M_BAD_PKT_TYPE'


class RpcProtMismatch(RpcException):
    msg = 'RPC_M_PROT_MISMATCH'


class RpcFragToobig(RpcException):
    msg = 'RPC_M_FRAG_TOOBIG'


class RpcUnsuppStubRtlIf(RpcException):
    msg = 'RPC_M_UNSUPP_STUB_RTL_IF'


class RpcUnhandledCallstate(RpcException):
    msg = 'RPC_M_UNHANDLED_CALLSTATE'


class RpcCallFailed(RpcException):
    msg = 'RPC_M_CALL_FAILED'


class RpcCallFailedNoStatus(RpcException):
    msg = 'RPC_M_CALL_FAILED_NO_STATUS'


class RpcCallFailedErrno(RpcException):
    msg = 'RPC_M_CALL_FAILED_ERRNO'


class RpcCallFailedS(RpcException):
    msg = 'RPC_M_CALL_FAILED_S'


class RpcCallFailedC(RpcException):
    msg = 'RPC_M_CALL_FAILED_C'


class RpcErrmsgToobig(RpcException):
    msg = 'RPC_M_ERRMSG_TOOBIG'


class RpcInvalidSrchattr(RpcException):
    msg = 'RPC_M_INVALID_SRCHATTR'


class RpcNtsNotFound(RpcException):
    msg = 'RPC_M_NTS_NOT_FOUND'


class RpcInvalidAccbytcnt(RpcException):
    msg = 'RPC_M_INVALID_ACCBYTCNT'


class RpcPreV2Ifspec(RpcException):
    msg = 'RPC_M_PRE_V2_IFSPEC'


class RpcUnkIfspec(RpcException):
    msg = 'RPC_M_UNK_IFSPEC'


class RpcRecvbufToosmall(RpcException):
    msg = 'RPC_M_RECVBUF_TOOSMALL'


class RpcUnalignAuthtrl(RpcException):
    msg = 'RPC_M_UNALIGN_AUTHTRL'


class RpcUnexpectedExc(RpcException):
    msg = 'RPC_M_UNEXPECTED_EXC'


class RpcNoStubData(RpcException):
    msg = 'RPC_M_NO_STUB_DATA'


class RpcEventlistFull(RpcException):
    msg = 'RPC_M_EVENTLIST_FULL'


class RpcUnkSockType(RpcException):
    msg = 'RPC_M_UNK_SOCK_TYPE'


class RpcUnimpCall(RpcException):
    msg = 'RPC_M_UNIMP_CALL'


class RpcInvalidSeqnum(RpcException):
    msg = 'RPC_M_INVALID_SEQNUM'


class RpcCantCreateUuid(RpcException):
    msg = 'RPC_M_CANT_CREATE_UUID'


class RpcPreV2Ss(RpcException):
    msg = 'RPC_M_PRE_V2_SS'


class RpcDgpktPoolCorrupt(RpcException):
    msg = 'RPC_M_DGPKT_POOL_CORRUPT'


class RpcDgpktBadFree(RpcException):
    msg = 'RPC_M_DGPKT_BAD_FREE'


class RpcLookasideCorrupt(RpcException):
    msg = 'RPC_M_LOOKASIDE_CORRUPT'


class RpcAllocFail(RpcException):
    msg = 'RPC_M_ALLOC_FAIL'


class RpcReallocFail(RpcException):
    msg = 'RPC_M_REALLOC_FAIL'


class RpcCantOpenFile(RpcException):
    msg = 'RPC_M_CANT_OPEN_FILE'


class RpcCantReadAddr(RpcException):
    msg = 'RPC_M_CANT_READ_ADDR'


class RpcSvcDescLibidl(RpcException):
    msg = 'RPC_SVC_DESC_LIBIDL'


class RpcCtxrundownNomem(RpcException):
    msg = 'RPC_M_CTXRUNDOWN_NOMEM'


class RpcCtxrundownExc(RpcException):
    msg = 'RPC_M_CTXRUNDOWN_EXC'


class RpcFaultCodesetConvError(RpcException):
    msg = 'RPC_S_FAULT_CODESET_CONV_ERROR'


class RpcNoCallActive(RpcException):
    msg = 'RPC_S_NO_CALL_ACTIVE'


class RpcCannotSupport(RpcException):
    msg = 'RPC_S_CANNOT_SUPPORT'


class RpcNoContextAvailable(RpcException):
    msg = 'RPC_S_NO_CONTEXT_AVAILABLE'


_RPC_EX_LOOKUP = {
    rpc_const.ACCESS_DENIED: AccessDenied,
    rpc_const.AUTHENTICATION_TYPE_NOT_RECOGNIZED:
        AuthenticationTypeNotRecognized,
    rpc_const.EPT_S_CANT_PERFORM_OP: EptCantPerformOp,
    rpc_const.RPC_S_INVALID_BOUND: RpcInvalidBound,
    rpc_const.RPC_S_CANNOT_SUPPORT: RpcCannotSupport,
    rpc_const.RPC_X_BAD_STUB_DATA: RpcBadStubData,
    rpc_const.NCA_S_COMM_FAILURE: NcaCommFailure,
    rpc_const.NCA_S_OP_RNG_ERROR: NcaOpRngError,
    rpc_const.NCA_S_UNK_IF: NcaUnkIf,
    rpc_const.NCA_S_WRONG_BOOT_TIME: NcaWrongBootTime,
    rpc_const.NCA_S_YOU_CRASHED: NcaYouCrashed,
    rpc_const.NCA_S_PROTO_ERROR: NcaProtoError,
    rpc_const.NCA_S_OUT_ARGS_TOO_BIG: NcaOutArgsTooBig,
    rpc_const.NCA_S_SERVER_TOO_BUSY: NcaServerTooBusy,
    rpc_const.NCA_S_FAULT_STRING_TOO_LONG: NcaFaultStringTooLong,
    rpc_const.NCA_S_UNSUPPORTED_TYPE: NcaUnsupportedType,
    rpc_const.NCA_S_FAULT_INT_DIV_BY_ZERO: NcaFaultIntDivByZero,
    rpc_const.NCA_S_FAULT_ADDR_ERROR: NcaFaultAddrError,
    rpc_const.NCA_S_FAULT_FP_DIV_ZERO: NcaFaultFpDivZero,
    rpc_const.NCA_S_FAULT_FP_UNDERFLOW: NcaFaultFpUnderflow,
    rpc_const.NCA_S_FAULT_FP_OVERFLOW: NcaFaultFpOverflow,
    rpc_const.NCA_S_FAULT_INVALID_TAG: NcaFaultInvalidTag,
    rpc_const.NCA_S_FAULT_INVALID_BOUND: NcaFaultInvalidBound,
    rpc_const.NCA_S_RPC_VERSION_MISMATCH: NcaRpcVersionMismatch,
    rpc_const.NCA_S_UNSPEC_REJECT: NcaUnspecReject,
    rpc_const.NCA_S_BAD_ACTID: NcaBadActid,
    rpc_const.NCA_S_WHO_ARE_YOU_FAILED: NcaWhoAreYouFailed,
    rpc_const.NCA_S_MANAGER_NOT_ENTERED: NcaManagerNotEntered,
    rpc_const.NCA_S_FAULT_CANCEL: NcaFaultCancel,
    rpc_const.NCA_S_FAULT_ILL_INST: NcaFaultIllInst,
    rpc_const.NCA_S_FAULT_FP_ERROR: NcaFaultFpError,
    rpc_const.NCA_S_FAULT_INT_OVERFLOW: NcaFaultIntOverflow,
    rpc_const.NCA_S_FAULT_UNSPEC: NcaFaultUnspec,
    rpc_const.NCA_S_FAULT_REMOTE_COMM_FAILURE: NcaFaultRemoteCommFailure,
    rpc_const.NCA_S_FAULT_PIPE_EMPTY: NcaFaultPipeEmpty,
    rpc_const.NCA_S_FAULT_PIPE_CLOSED: NcaFaultPipeClosed,
    rpc_const.NCA_S_FAULT_PIPE_ORDER: NcaFaultPipeOrder,
    rpc_const.NCA_S_FAULT_PIPE_DISCIPLINE: NcaFaultPipeDiscipline,
    rpc_const.NCA_S_FAULT_PIPE_COMM_ERROR: NcaFaultPipeCommError,
    rpc_const.NCA_S_FAULT_PIPE_MEMORY: NcaFaultPipeMemory,
    rpc_const.NCA_S_FAULT_CONTEXT_MISMATCH: NcaFaultContextMismatch,
    rpc_const.NCA_S_FAULT_REMOTE_NO_MEMORY: NcaFaultRemoteNoMemory,
    rpc_const.NCA_S_INVALID_PRES_CONTEXT_ID: NcaInvalidPresContextId,
    rpc_const.NCA_S_UNSUPPORTED_AUTHN_LEVEL: NcaUnsupportedAuthnLevel,
    rpc_const.NCA_S_INVALID_CHECKSUM: NcaInvalidChecksum,
    rpc_const.NCA_S_INVALID_CRC: NcaInvalidCrc,
    rpc_const.NCA_S_FAULT_USER_DEFINED: NcaFaultUserDefined,
    rpc_const.NCA_S_FAULT_TX_OPEN_FAILED: NcaFaultTxOpenFailed,
    rpc_const.NCA_S_FAULT_CODESET_CONV_ERROR: NcaFaultCodesetConvError,
    rpc_const.NCA_S_FAULT_OBJECT_NOT_FOUND: NcaFaultObjectNotFound,
    rpc_const.NCA_S_FAULT_NO_CLIENT_STUB: NcaFaultNoClientStub,
    rpc_const.RPC_S_MOD: RpcMod,
    rpc_const.RPC_S_OP_RNG_ERROR: RpcOpRngError,
    rpc_const.RPC_S_CANT_CREATE_SOCKET: RpcCantCreateSocket,
    rpc_const.RPC_S_CANT_BIND_SOCKET: RpcCantBindSocket,
    rpc_const.RPC_S_NOT_IN_CALL: RpcNotInCall,
    rpc_const.RPC_S_NO_PORT: RpcNoPort,
    rpc_const.RPC_S_WRONG_BOOT_TIME: RpcWrongBootTime,
    rpc_const.RPC_S_TOO_MANY_SOCKETS: RpcTooManySockets,
    rpc_const.RPC_S_ILLEGAL_REGISTER: RpcIllegalRegister,
    rpc_const.RPC_S_CANT_RECV: RpcCantRecv,
    rpc_const.RPC_S_BAD_PKT: RpcBadPkt,
    rpc_const.RPC_S_UNBOUND_HANDLE: RpcUnboundHandle,
    rpc_const.RPC_S_ADDR_IN_USE: RpcAddrInUse,
    rpc_const.RPC_S_IN_ARGS_TOO_BIG: RpcInArgsTooBig,
    rpc_const.RPC_S_STRING_TOO_LONG: RpcStringTooLong,
    rpc_const.RPC_S_TOO_MANY_OBJECTS: RpcTooManyObjects,
    rpc_const.RPC_S_BINDING_HAS_NO_AUTH: RpcBindingHasNoAuth,
    rpc_const.RPC_S_UNKNOWN_AUTHN_SERVICE: RpcUnknownAuthnService,
    rpc_const.RPC_S_NO_MEMORY: RpcNoMemory,
    rpc_const.RPC_S_CANT_NMALLOC: RpcCantNmalloc,
    rpc_const.RPC_S_CALL_FAULTED: RpcCallFaulted,
    rpc_const.RPC_S_CALL_FAILED: RpcCallFailed,
    rpc_const.RPC_S_COMM_FAILURE: RpcCommFailure,
    rpc_const.RPC_S_RPCD_COMM_FAILURE: RpcRpcdCommFailure,
    rpc_const.RPC_S_ILLEGAL_FAMILY_REBIND: RpcIllegalFamilyRebind,
    rpc_const.RPC_S_INVALID_HANDLE: RpcInvalidHandle,
    rpc_const.RPC_S_CODING_ERROR: RpcCodingError,
    rpc_const.RPC_S_OBJECT_NOT_FOUND: RpcObjectNotFound,
    rpc_const.RPC_S_CTHREAD_NOT_FOUND: RpcCthreadNotFound,
    rpc_const.RPC_S_INVALID_BINDING: RpcInvalidBinding,
    rpc_const.RPC_S_ALREADY_REGISTERED: RpcAlreadyRegistered,
    rpc_const.RPC_S_ENDPOINT_NOT_FOUND: RpcEndpointNotFound,
    rpc_const.RPC_S_INVALID_RPC_PROTSEQ: RpcInvalidRpcProtseq,
    rpc_const.RPC_S_DESC_NOT_REGISTERED: RpcDescNotRegistered,
    rpc_const.RPC_S_ALREADY_LISTENING: RpcAlreadyListening,
    rpc_const.RPC_S_NO_PROTSEQS: RpcNoProtseqs,
    rpc_const.RPC_S_NO_PROTSEQS_REGISTERED: RpcNoProtseqsRegistered,
    rpc_const.RPC_S_NO_BINDINGS: RpcNoBindings,
    rpc_const.RPC_S_MAX_DESCS_EXCEEDED: RpcMaxDescsExceeded,
    rpc_const.RPC_S_NO_INTERFACES: RpcNoInterfaces,
    rpc_const.RPC_S_INVALID_TIMEOUT: RpcInvalidTimeout,
    rpc_const.RPC_S_CANT_INQ_SOCKET: RpcCantInqSocket,
    rpc_const.RPC_S_INVALID_NAF_ID: RpcInvalidNafId,
    rpc_const.RPC_S_INVAL_NET_ADDR: RpcInvalNetAddr,
    rpc_const.RPC_S_UNKNOWN_IF: RpcUnknownIf,
    rpc_const.RPC_S_UNSUPPORTED_TYPE: RpcUnsupportedType,
    rpc_const.RPC_S_INVALID_CALL_OPT: RpcInvalidCallOpt,
    rpc_const.RPC_S_NO_FAULT: RpcNoFault,
    rpc_const.RPC_S_CANCEL_TIMEOUT: RpcCancelTimeout,
    rpc_const.RPC_S_CALL_CANCELLED: RpcCallCancelled,
    rpc_const.RPC_S_INVALID_CALL_HANDLE: RpcInvalidCallHandle,
    rpc_const.RPC_S_CANNOT_ALLOC_ASSOC: RpcCannotAllocAssoc,
    rpc_const.RPC_S_CANNOT_CONNECT: RpcCannotConnect,
    rpc_const.RPC_S_CONNECTION_ABORTED: RpcConnectionAborted,
    rpc_const.RPC_S_CONNECTION_CLOSED: RpcConnectionClosed,
    rpc_const.RPC_S_CANNOT_ACCEPT: RpcCannotAccept,
    rpc_const.RPC_S_ASSOC_GRP_NOT_FOUND: RpcAssocGrpNotFound,
    rpc_const.RPC_S_STUB_INTERFACE_ERROR: RpcStubInterfaceError,
    rpc_const.RPC_S_INVALID_OBJECT: RpcInvalidObject,
    rpc_const.RPC_S_INVALID_TYPE: RpcInvalidType,
    rpc_const.RPC_S_INVALID_IF_OPNUM: RpcInvalidIfOpnum,
    rpc_const.RPC_S_DIFFERENT_SERVER_INSTANCE: RpcDifferentServerInstance,
    rpc_const.RPC_S_PROTOCOL_ERROR: RpcProtocolError,
    rpc_const.RPC_S_CANT_RECVMSG: RpcCantRecvmsg,
    rpc_const.RPC_S_INVALID_STRING_BINDING: RpcInvalidStringBinding,
    rpc_const.RPC_S_CONNECT_TIMED_OUT: RpcConnectTimedOut,
    rpc_const.RPC_S_CONNECT_REJECTED: RpcConnectRejected,
    rpc_const.RPC_S_NETWORK_UNREACHABLE: RpcNetworkUnreachable,
    rpc_const.RPC_S_CONNECT_NO_RESOURCES: RpcConnectNoResources,
    rpc_const.RPC_S_REM_NETWORK_SHUTDOWN: RpcRemNetworkShutdown,
    rpc_const.RPC_S_TOO_MANY_REM_CONNECTS: RpcTooManyRemConnects,
    rpc_const.RPC_S_NO_REM_ENDPOINT: RpcNoRemEndpoint,
    rpc_const.RPC_S_REM_HOST_DOWN: RpcRemHostDown,
    rpc_const.RPC_S_HOST_UNREACHABLE: RpcHostUnreachable,
    rpc_const.RPC_S_ACCESS_CONTROL_INFO_INV: RpcAccessControlInfoInv,
    rpc_const.RPC_S_LOC_CONNECT_ABORTED: RpcLocConnectAborted,
    rpc_const.RPC_S_CONNECT_CLOSED_BY_REM: RpcConnectClosedByRem,
    rpc_const.RPC_S_REM_HOST_CRASHED: RpcRemHostCrashed,
    rpc_const.RPC_S_INVALID_ENDPOINT_FORMAT: RpcInvalidEndpointFormat,
    rpc_const.RPC_S_UNKNOWN_STATUS_CODE: RpcUnknownStatusCode,
    rpc_const.RPC_S_UNKNOWN_MGR_TYPE: RpcUnknownMgrType,
    rpc_const.RPC_S_ASSOC_CREATION_FAILED: RpcAssocCreationFailed,
    rpc_const.RPC_S_ASSOC_GRP_MAX_EXCEEDED: RpcAssocGrpMaxExceeded,
    rpc_const.RPC_S_ASSOC_GRP_ALLOC_FAILED: RpcAssocGrpAllocFailed,
    rpc_const.RPC_S_SM_INVALID_STATE: RpcSmInvalidState,
    rpc_const.RPC_S_ASSOC_REQ_REJECTED: RpcAssocReqRejected,
    rpc_const.RPC_S_ASSOC_SHUTDOWN: RpcAssocShutdown,
    rpc_const.RPC_S_TSYNTAXES_UNSUPPORTED: RpcTsyntaxesUnsupported,
    rpc_const.RPC_S_CONTEXT_ID_NOT_FOUND: RpcContextIdNotFound,
    rpc_const.RPC_S_CANT_LISTEN_SOCKET: RpcCantListenSocket,
    rpc_const.RPC_S_NO_ADDRS: RpcNoAddrs,
    rpc_const.RPC_S_CANT_GETPEERNAME: RpcCantGetpeername,
    rpc_const.RPC_S_CANT_GET_IF_ID: RpcCantGetIfId,
    rpc_const.RPC_S_PROTSEQ_NOT_SUPPORTED: RpcProtseqNotSupported,
    rpc_const.RPC_S_CALL_ORPHANED: RpcCallOrphaned,
    rpc_const.RPC_S_WHO_ARE_YOU_FAILED: RpcWhoAreYouFailed,
    rpc_const.RPC_S_UNKNOWN_REJECT: RpcUnknownReject,
    rpc_const.RPC_S_TYPE_ALREADY_REGISTERED: RpcTypeAlreadyRegistered,
    rpc_const.RPC_S_STOP_LISTENING_DISABLED: RpcStopListeningDisabled,
    rpc_const.RPC_S_INVALID_ARG: RpcInvalidArg,
    rpc_const.RPC_S_NOT_SUPPORTED: RpcNotSupported,
    rpc_const.RPC_S_WRONG_KIND_OF_BINDING: RpcWrongKindOfBinding,
    rpc_const.RPC_S_AUTHN_AUTHZ_MISMATCH: RpcAuthnAuthzMismatch,
    rpc_const.RPC_S_CALL_QUEUED: RpcCallQueued,
    rpc_const.RPC_S_CANNOT_SET_NODELAY: RpcCannotSetNodelay,
    rpc_const.RPC_S_NOT_RPC_TOWER: RpcNotRpcTower,
    rpc_const.RPC_S_INVALID_RPC_PROTID: RpcInvalidRpcProtid,
    rpc_const.RPC_S_INVALID_RPC_FLOOR: RpcInvalidRpcFloor,
    rpc_const.RPC_S_CALL_TIMEOUT: RpcCallTimeout,
    rpc_const.RPC_S_MGMT_OP_DISALLOWED: RpcMgmtOpDisallowed,
    rpc_const.RPC_S_MANAGER_NOT_ENTERED: RpcManagerNotEntered,
    rpc_const.RPC_S_CALLS_TOO_LARGE_FOR_WK_EP: RpcCallsTooLargeForWkEp,
    rpc_const.RPC_S_SERVER_TOO_BUSY: RpcServerTooBusy,
    rpc_const.RPC_S_PROT_VERSION_MISMATCH: RpcProtVersionMismatch,
    rpc_const.RPC_S_RPC_PROT_VERSION_MISMATCH: RpcRpcProtVersionMismatch,
    rpc_const.RPC_S_SS_NO_IMPORT_CURSOR: RpcSsNoImportCursor,
    rpc_const.RPC_S_FAULT_ADDR_ERROR: RpcFaultAddrError,
    rpc_const.RPC_S_FAULT_CONTEXT_MISMATCH: RpcFaultContextMismatch,
    rpc_const.RPC_S_FAULT_FP_DIV_BY_ZERO: RpcFaultFpDivByZero,
    rpc_const.RPC_S_FAULT_FP_ERROR: RpcFaultFpError,
    rpc_const.RPC_S_FAULT_FP_OVERFLOW: RpcFaultFpOverflow,
    rpc_const.RPC_S_FAULT_FP_UNDERFLOW: RpcFaultFpUnderflow,
    rpc_const.RPC_S_FAULT_ILL_INST: RpcFaultIllInst,
    rpc_const.RPC_S_FAULT_INT_DIV_BY_ZERO: RpcFaultIntDivByZero,
    rpc_const.RPC_S_FAULT_INT_OVERFLOW: RpcFaultIntOverflow,
    rpc_const.RPC_S_FAULT_INVALID_BOUND: RpcFaultInvalidBound,
    rpc_const.RPC_S_FAULT_INVALID_TAG: RpcFaultInvalidTag,
    rpc_const.RPC_S_FAULT_PIPE_CLOSED: RpcFaultPipeClosed,
    rpc_const.RPC_S_FAULT_PIPE_COMM_ERROR: RpcFaultPipeCommError,
    rpc_const.RPC_S_FAULT_PIPE_DISCIPLINE: RpcFaultPipeDiscipline,
    rpc_const.RPC_S_FAULT_PIPE_EMPTY: RpcFaultPipeEmpty,
    rpc_const.RPC_S_FAULT_PIPE_MEMORY: RpcFaultPipeMemory,
    rpc_const.RPC_S_FAULT_PIPE_ORDER: RpcFaultPipeOrder,
    rpc_const.RPC_S_FAULT_REMOTE_COMM_FAILURE: RpcFaultRemoteCommFailure,
    rpc_const.RPC_S_FAULT_REMOTE_NO_MEMORY: RpcFaultRemoteNoMemory,
    rpc_const.RPC_S_FAULT_UNSPEC: RpcFaultUnspec,
    rpc_const.UUID_S_BAD_VERSION: UuidBadVersion,
    rpc_const.UUID_S_SOCKET_FAILURE: UuidSocketFailure,
    rpc_const.UUID_S_GETCONF_FAILURE: UuidGetconfFailure,
    rpc_const.UUID_S_NO_ADDRESS: UuidNoAddress,
    rpc_const.UUID_S_OVERRUN: UuidOverrun,
    rpc_const.UUID_S_INTERNAL_ERROR: UuidInternalError,
    rpc_const.UUID_S_CODING_ERROR: UuidCodingError,
    rpc_const.UUID_S_INVALID_STRING_UUID: UuidInvalidStringUuid,
    rpc_const.UUID_S_NO_MEMORY: UuidNoMemory,
    rpc_const.RPC_S_NO_MORE_ENTRIES: RpcNoMoreEntries,
    rpc_const.RPC_S_UNKNOWN_NS_ERROR: RpcUnknownNsError,
    rpc_const.RPC_S_NAME_SERVICE_UNAVAILABLE: RpcNameServiceUnavailable,
    rpc_const.RPC_S_INCOMPLETE_NAME: RpcIncompleteName,
    rpc_const.RPC_S_GROUP_NOT_FOUND: RpcGroupNotFound,
    rpc_const.RPC_S_INVALID_NAME_SYNTAX: RpcInvalidNameSyntax,
    rpc_const.RPC_S_NO_MORE_MEMBERS: RpcNoMoreMembers,
    rpc_const.RPC_S_NO_MORE_INTERFACES: RpcNoMoreInterfaces,
    rpc_const.RPC_S_INVALID_NAME_SERVICE: RpcInvalidNameService,
    rpc_const.RPC_S_NO_NAME_MAPPING: RpcNoNameMapping,
    rpc_const.RPC_S_PROFILE_NOT_FOUND: RpcProfileNotFound,
    rpc_const.RPC_S_NOT_FOUND: RpcNotFound,
    rpc_const.RPC_S_NO_UPDATES: RpcNoUpdates,
    rpc_const.RPC_S_UPDATE_FAILED: RpcUpdateFailed,
    rpc_const.RPC_S_NO_MATCH_EXPORTED: RpcNoMatchExported,
    rpc_const.RPC_S_ENTRY_NOT_FOUND: RpcEntryNotFound,
    rpc_const.RPC_S_INVALID_INQUIRY_CONTEXT: RpcInvalidInquiryContext,
    rpc_const.RPC_S_INTERFACE_NOT_FOUND: RpcInterfaceNotFound,
    rpc_const.RPC_S_GROUP_MEMBER_NOT_FOUND: RpcGroupMemberNotFound,
    rpc_const.RPC_S_ENTRY_ALREADY_EXISTS: RpcEntryAlreadyExists,
    rpc_const.RPC_S_NSINIT_FAILURE: RpcNsinitFailure,
    rpc_const.RPC_S_UNSUPPORTED_NAME_SYNTAX: RpcUnsupportedNameSyntax,
    rpc_const.RPC_S_NO_MORE_ELEMENTS: RpcNoMoreElements,
    rpc_const.RPC_S_NO_NS_PERMISSION: RpcNoNsPermission,
    rpc_const.RPC_S_INVALID_INQUIRY_TYPE: RpcInvalidInquiryType,
    rpc_const.RPC_S_PROFILE_ELEMENT_NOT_FOUND: RpcProfileElementNotFound,
    rpc_const.RPC_S_PROFILE_ELEMENT_REPLACED: RpcProfileElementReplaced,
    rpc_const.RPC_S_IMPORT_ALREADY_DONE: RpcImportAlreadyDone,
    rpc_const.RPC_S_DATABASE_BUSY: RpcDatabaseBusy,
    rpc_const.RPC_S_INVALID_IMPORT_CONTEXT: RpcInvalidImportContext,
    rpc_const.RPC_S_UUID_SET_NOT_FOUND: RpcUuidSetNotFound,
    rpc_const.RPC_S_UUID_MEMBER_NOT_FOUND: RpcUuidMemberNotFound,
    rpc_const.RPC_S_NO_INTERFACES_EXPORTED: RpcNoInterfacesExported,
    rpc_const.RPC_S_TOWER_SET_NOT_FOUND: RpcTowerSetNotFound,
    rpc_const.RPC_S_TOWER_MEMBER_NOT_FOUND: RpcTowerMemberNotFound,
    rpc_const.RPC_S_OBJ_UUID_NOT_FOUND: RpcObjUuidNotFound,
    rpc_const.RPC_S_NO_MORE_BINDINGS: RpcNoMoreBindings,
    rpc_const.RPC_S_INVALID_PRIORITY: RpcInvalidPriority,
    rpc_const.RPC_S_NOT_RPC_ENTRY: RpcNotRpcEntry,
    rpc_const.RPC_S_INVALID_LOOKUP_CONTEXT: RpcInvalidLookupContext,
    rpc_const.RPC_S_BINDING_VECTOR_FULL: RpcBindingVectorFull,
    rpc_const.RPC_S_CYCLE_DETECTED: RpcCycleDetected,
    rpc_const.RPC_S_NOTHING_TO_EXPORT: RpcNothingToExport,
    rpc_const.RPC_S_NOTHING_TO_UNEXPORT: RpcNothingToUnexport,
    rpc_const.RPC_S_INVALID_VERS_OPTION: RpcInvalidVersOption,
    rpc_const.RPC_S_NO_RPC_DATA: RpcNoRpcData,
    rpc_const.RPC_S_MBR_PICKED: RpcMbrPicked,
    rpc_const.RPC_S_NOT_ALL_OBJS_UNEXPORTED: RpcNotAllObjsUnexported,
    rpc_const.RPC_S_NO_ENTRY_NAME: RpcNoEntryName,
    rpc_const.RPC_S_PRIORITY_GROUP_DONE: RpcPriorityGroupDone,
    rpc_const.RPC_S_PARTIAL_RESULTS: RpcPartialResults,
    rpc_const.RPC_S_NO_ENV_SETUP: RpcNoEnvSetup,
    rpc_const.TWR_S_UNKNOWN_SA: TwrUnknownSa,
    rpc_const.TWR_S_UNKNOWN_TOWER: TwrUnknownTower,
    rpc_const.TWR_S_NOT_IMPLEMENTED: TwrNotImplemented,
    rpc_const.RPC_S_MAX_CALLS_TOO_SMALL: RpcMaxCallsTooSmall,
    rpc_const.RPC_S_CTHREAD_CREATE_FAILED: RpcCthreadCreateFailed,
    rpc_const.RPC_S_CTHREAD_POOL_EXISTS: RpcCthreadPoolExists,
    rpc_const.RPC_S_CTHREAD_NO_SUCH_POOL: RpcCthreadNoSuchPool,
    rpc_const.RPC_S_CTHREAD_INVOKE_DISABLED: RpcCthreadInvokeDisabled,
    rpc_const.EPT_S_CANT_PERFORM_OP: EptCantPerformOp,
    rpc_const.EPT_S_NO_MEMORY: EptNoMemory,
    rpc_const.EPT_S_DATABASE_INVALID: EptDatabaseInvalid,
    rpc_const.EPT_S_CANT_CREATE: EptCantCreate,
    rpc_const.EPT_S_CANT_ACCESS: EptCantAccess,
    rpc_const.EPT_S_DATABASE_ALREADY_OPEN: EptDatabaseAlreadyOpen,
    rpc_const.EPT_S_INVALID_ENTRY: EptInvalidEntry,
    rpc_const.EPT_S_UPDATE_FAILED: EptUpdateFailed,
    rpc_const.EPT_S_INVALID_CONTEXT: EptInvalidContext,
    rpc_const.EPT_S_NOT_REGISTERED: EptNotRegistered,
    rpc_const.EPT_S_SERVER_UNAVAILABLE: EptServerUnavailable,
    rpc_const.RPC_S_UNDERSPECIFIED_NAME: RpcUnderspecifiedName,
    rpc_const.RPC_S_INVALID_NS_HANDLE: RpcInvalidNsHandle,
    rpc_const.RPC_S_UNKNOWN_ERROR: RpcUnknownError,
    rpc_const.RPC_S_SS_CHAR_TRANS_OPEN_FAIL: RpcSsCharTransOpenFail,
    rpc_const.RPC_S_SS_CHAR_TRANS_SHORT_FILE: RpcSsCharTransShortFile,
    rpc_const.RPC_S_SS_CONTEXT_DAMAGED: RpcSsContextDamaged,
    rpc_const.RPC_S_SS_IN_NULL_CONTEXT: RpcSsInNullContext,
    rpc_const.RPC_S_SOCKET_FAILURE: RpcSocketFailure,
    rpc_const.RPC_S_UNSUPPORTED_PROTECT_LEVEL: RpcUnsupportedProtectLevel,
    rpc_const.RPC_S_INVALID_CHECKSUM: RpcInvalidChecksum,
    rpc_const.RPC_S_INVALID_CREDENTIALS: RpcInvalidCredentials,
    rpc_const.RPC_S_CREDENTIALS_TOO_LARGE: RpcCredentialsTooLarge,
    rpc_const.RPC_S_CALL_ID_NOT_FOUND: RpcCallIdNotFound,
    rpc_const.RPC_S_KEY_ID_NOT_FOUND: RpcKeyIdNotFound,
    rpc_const.RPC_S_AUTH_BAD_INTEGRITY: RpcAuthBadIntegrity,
    rpc_const.RPC_S_AUTH_TKT_EXPIRED: RpcAuthTktExpired,
    rpc_const.RPC_S_AUTH_TKT_NYV: RpcAuthTktNyv,
    rpc_const.RPC_S_AUTH_REPEAT: RpcAuthRepeat,
    rpc_const.RPC_S_AUTH_NOT_US: RpcAuthNotUs,
    rpc_const.RPC_S_AUTH_BADMATCH: RpcAuthBadmatch,
    rpc_const.RPC_S_AUTH_SKEW: RpcAuthSkew,
    rpc_const.RPC_S_AUTH_BADADDR: RpcAuthBadaddr,
    rpc_const.RPC_S_AUTH_BADVERSION: RpcAuthBadversion,
    rpc_const.RPC_S_AUTH_MSG_TYPE: RpcAuthMsgType,
    rpc_const.RPC_S_AUTH_MODIFIED: RpcAuthModified,
    rpc_const.RPC_S_AUTH_BADORDER: RpcAuthBadorder,
    rpc_const.RPC_S_AUTH_BADKEYVER: RpcAuthBadkeyver,
    rpc_const.RPC_S_AUTH_NOKEY: RpcAuthNokey,
    rpc_const.RPC_S_AUTH_MUT_FAIL: RpcAuthMutFail,
    rpc_const.RPC_S_AUTH_BADDIRECTION: RpcAuthBaddirection,
    rpc_const.RPC_S_AUTH_METHOD: RpcAuthMethod,
    rpc_const.RPC_S_AUTH_BADSEQ: RpcAuthBadseq,
    rpc_const.RPC_S_AUTH_INAPP_CKSUM: RpcAuthInappCksum,
    rpc_const.RPC_S_AUTH_FIELD_TOOLONG: RpcAuthFieldToolong,
    rpc_const.RPC_S_INVALID_CRC: RpcInvalidCrc,
    rpc_const.RPC_S_BINDING_INCOMPLETE: RpcBindingIncomplete,
    rpc_const.RPC_S_KEY_FUNC_NOT_ALLOWED: RpcKeyFuncNotAllowed,
    rpc_const.RPC_S_UNKNOWN_STUB_RTL_IF_VERS: RpcUnknownStubRtlIfVers,
    rpc_const.RPC_S_UNKNOWN_IFSPEC_VERS: RpcUnknownIfspecVers,
    rpc_const.RPC_S_PROTO_UNSUPP_BY_AUTH: RpcProtoUnsuppByAuth,
    rpc_const.RPC_S_AUTHN_CHALLENGE_MALFORMED: RpcAuthnChallengeMalformed,
    rpc_const.RPC_S_PROTECT_LEVEL_MISMATCH: RpcProtectLevelMismatch,
    rpc_const.RPC_S_NO_MEPV: RpcNoMepv,
    rpc_const.RPC_S_STUB_PROTOCOL_ERROR: RpcStubProtocolError,
    rpc_const.RPC_S_CLASS_VERSION_MISMATCH: RpcClassVersionMismatch,
    rpc_const.RPC_S_HELPER_NOT_RUNNING: RpcHelperNotRunning,
    rpc_const.RPC_S_HELPER_SHORT_READ: RpcHelperShortRead,
    rpc_const.RPC_S_HELPER_CATATONIC: RpcHelperCatatonic,
    rpc_const.RPC_S_HELPER_ABORTED: RpcHelperAborted,
    rpc_const.RPC_S_NOT_IN_KERNEL: RpcNotInKernel,
    rpc_const.RPC_S_HELPER_WRONG_USER: RpcHelperWrongUser,
    rpc_const.RPC_S_HELPER_OVERFLOW: RpcHelperOverflow,
    rpc_const.RPC_S_DG_NEED_WAY_AUTH: RpcDgNeedWayAuth,
    rpc_const.RPC_S_UNSUPPORTED_AUTH_SUBTYPE: RpcUnsupportedAuthSubtype,
    rpc_const.RPC_S_WRONG_PICKLE_TYPE: RpcWrongPickleType,
    rpc_const.RPC_S_NOT_LISTENING: RpcNotListening,
    rpc_const.RPC_S_SS_BAD_BUFFER: RpcSsBadBuffer,
    rpc_const.RPC_S_SS_BAD_ES_ACTION: RpcSsBadEsAction,
    rpc_const.RPC_S_SS_WRONG_ES_VERSION: RpcSsWrongEsVersion,
    rpc_const.RPC_S_FAULT_USER_DEFINED: RpcFaultUserDefined,
    rpc_const.RPC_S_SS_INCOMPATIBLE_CODESETS: RpcSsIncompatibleCodesets,
    rpc_const.RPC_S_TX_NOT_IN_TRANSACTION: RpcTxNotInTransaction,
    rpc_const.RPC_S_TX_OPEN_FAILED: RpcTxOpenFailed,
    rpc_const.RPC_S_PARTIAL_CREDENTIALS: RpcPartialCredentials,
    rpc_const.RPC_S_SS_INVALID_CODESET_TAG: RpcSsInvalidCodesetTag,
    rpc_const.RPC_S_MGMT_BAD_TYPE: RpcMgmtBadType,
    rpc_const.RPC_S_SS_INVALID_CHAR_INPUT: RpcSsInvalidCharInput,
    rpc_const.RPC_S_SS_SHORT_CONV_BUFFER: RpcSsShortConvBuffer,
    rpc_const.RPC_S_SS_ICONV_ERROR: RpcSsIconvError,
    rpc_const.RPC_S_SS_NO_COMPAT_CODESET: RpcSsNoCompatCodeset,
    rpc_const.RPC_S_SS_NO_COMPAT_CHARSETS: RpcSsNoCompatCharsets,
    rpc_const.DCE_CS_C_OK: DceCsOk,
    rpc_const.DCE_CS_C_UNKNOWN: DceCsUnknown,
    rpc_const.DCE_CS_C_NOTFOUND: DceCsNotfound,
    rpc_const.DCE_CS_C_CANNOT_OPEN_FILE: DceCsCannotOpenFile,
    rpc_const.DCE_CS_C_CANNOT_READ_FILE: DceCsCannotReadFile,
    rpc_const.DCE_CS_C_CANNOT_ALLOCATE_MEMORY: DceCsCannotAllocateMemory,
    rpc_const.RPC_S_SS_CLEANUP_FAILED: RpcSsCleanupFailed,
    rpc_const.RPC_SVC_DESC_GENERAL: RpcSvcDescGeneral,
    rpc_const.RPC_SVC_DESC_MUTEX: RpcSvcDescMutex,
    rpc_const.RPC_SVC_DESC_XMIT: RpcSvcDescXmit,
    rpc_const.RPC_SVC_DESC_RECV: RpcSvcDescRecv,
    rpc_const.RPC_SVC_DESC_DG_STATE: RpcSvcDescDgState,
    rpc_const.RPC_SVC_DESC_CANCEL: RpcSvcDescCancel,
    rpc_const.RPC_SVC_DESC_ORPHAN: RpcSvcDescOrphan,
    rpc_const.RPC_SVC_DESC_CN_STATE: RpcSvcDescCnState,
    rpc_const.RPC_SVC_DESC_CN_PKT: RpcSvcDescCnPkt,
    rpc_const.RPC_SVC_DESC_PKT_QUOTAS: RpcSvcDescPktQuotas,
    rpc_const.RPC_SVC_DESC_AUTH: RpcSvcDescAuth,
    rpc_const.RPC_SVC_DESC_SOURCE: RpcSvcDescSource,
    rpc_const.RPC_SVC_DESC_STATS: RpcSvcDescStats,
    rpc_const.RPC_SVC_DESC_MEM: RpcSvcDescMem,
    rpc_const.RPC_SVC_DESC_MEM_TYPE: RpcSvcDescMemType,
    rpc_const.RPC_SVC_DESC_DG_PKTLOG: RpcSvcDescDgPktlog,
    rpc_const.RPC_SVC_DESC_THREAD_ID: RpcSvcDescThreadId,
    rpc_const.RPC_SVC_DESC_TIMESTAMP: RpcSvcDescTimestamp,
    rpc_const.RPC_SVC_DESC_CN_ERRORS: RpcSvcDescCnErrors,
    rpc_const.RPC_SVC_DESC_CONV_THREAD: RpcSvcDescConvThread,
    rpc_const.RPC_SVC_DESC_PID: RpcSvcDescPid,
    rpc_const.RPC_SVC_DESC_ATFORK: RpcSvcDescAtfork,
    rpc_const.RPC_SVC_DESC_CMA_THREAD: RpcSvcDescCmaThread,
    rpc_const.RPC_SVC_DESC_INHERIT: RpcSvcDescInherit,
    rpc_const.RPC_SVC_DESC_DG_SOCKETS: RpcSvcDescDgSockets,
    rpc_const.RPC_SVC_DESC_TIMER: RpcSvcDescTimer,
    rpc_const.RPC_SVC_DESC_THREADS: RpcSvcDescThreads,
    rpc_const.RPC_SVC_DESC_SERVER_CALL: RpcSvcDescServerCall,
    rpc_const.RPC_SVC_DESC_NSI: RpcSvcDescNsi,
    rpc_const.RPC_SVC_DESC_DG_PKT: RpcSvcDescDgPkt,
    rpc_const.RPC_M_CN_ILL_STATE_TRANS_SA: RpcCnIllStateTransSa,
    rpc_const.RPC_M_CN_ILL_STATE_TRANS_CA: RpcCnIllStateTransCa,
    rpc_const.RPC_M_CN_ILL_STATE_TRANS_SG: RpcCnIllStateTransSg,
    rpc_const.RPC_M_CN_ILL_STATE_TRANS_CG: RpcCnIllStateTransCg,
    rpc_const.RPC_M_CN_ILL_STATE_TRANS_SR: RpcCnIllStateTransSr,
    rpc_const.RPC_M_CN_ILL_STATE_TRANS_CR: RpcCnIllStateTransCr,
    rpc_const.RPC_M_BAD_PKT_TYPE: RpcBadPktType,
    rpc_const.RPC_M_PROT_MISMATCH: RpcProtMismatch,
    rpc_const.RPC_M_FRAG_TOOBIG: RpcFragToobig,
    rpc_const.RPC_M_UNSUPP_STUB_RTL_IF: RpcUnsuppStubRtlIf,
    rpc_const.RPC_M_UNHANDLED_CALLSTATE: RpcUnhandledCallstate,
    rpc_const.RPC_M_CALL_FAILED: RpcCallFailed,
    rpc_const.RPC_M_CALL_FAILED_NO_STATUS: RpcCallFailedNoStatus,
    rpc_const.RPC_M_CALL_FAILED_ERRNO: RpcCallFailedErrno,
    rpc_const.RPC_M_CALL_FAILED_S: RpcCallFailedS,
    rpc_const.RPC_M_CALL_FAILED_C: RpcCallFailedC,
    rpc_const.RPC_M_ERRMSG_TOOBIG: RpcErrmsgToobig,
    rpc_const.RPC_M_INVALID_SRCHATTR: RpcInvalidSrchattr,
    rpc_const.RPC_M_NTS_NOT_FOUND: RpcNtsNotFound,
    rpc_const.RPC_M_INVALID_ACCBYTCNT: RpcInvalidAccbytcnt,
    rpc_const.RPC_M_PRE_V2_IFSPEC: RpcPreV2Ifspec,
    rpc_const.RPC_M_UNK_IFSPEC: RpcUnkIfspec,
    rpc_const.RPC_M_RECVBUF_TOOSMALL: RpcRecvbufToosmall,
    rpc_const.RPC_M_UNALIGN_AUTHTRL: RpcUnalignAuthtrl,
    rpc_const.RPC_M_UNEXPECTED_EXC: RpcUnexpectedExc,
    rpc_const.RPC_M_NO_STUB_DATA: RpcNoStubData,
    rpc_const.RPC_M_EVENTLIST_FULL: RpcEventlistFull,
    rpc_const.RPC_M_UNK_SOCK_TYPE: RpcUnkSockType,
    rpc_const.RPC_M_UNIMP_CALL: RpcUnimpCall,
    rpc_const.RPC_M_INVALID_SEQNUM: RpcInvalidSeqnum,
    rpc_const.RPC_M_CANT_CREATE_UUID: RpcCantCreateUuid,
    rpc_const.RPC_M_PRE_V2_SS: RpcPreV2Ss,
    rpc_const.RPC_M_DGPKT_POOL_CORRUPT: RpcDgpktPoolCorrupt,
    rpc_const.RPC_M_DGPKT_BAD_FREE: RpcDgpktBadFree,
    rpc_const.RPC_M_LOOKASIDE_CORRUPT: RpcLookasideCorrupt,
    rpc_const.RPC_M_ALLOC_FAIL: RpcAllocFail,
    rpc_const.RPC_M_REALLOC_FAIL: RpcReallocFail,
    rpc_const.RPC_M_CANT_OPEN_FILE: RpcCantOpenFile,
    rpc_const.RPC_M_CANT_READ_ADDR: RpcCantReadAddr,
    rpc_const.RPC_SVC_DESC_LIBIDL: RpcSvcDescLibidl,
    rpc_const.RPC_M_CTXRUNDOWN_NOMEM: RpcCtxrundownNomem,
    rpc_const.RPC_M_CTXRUNDOWN_EXC: RpcCtxrundownExc,
    rpc_const.RPC_S_FAULT_CODESET_CONV_ERROR: RpcFaultCodesetConvError,
    rpc_const.RPC_S_NO_CALL_ACTIVE: RpcNoCallActive,
    rpc_const.RPC_S_CANNOT_SUPPORT: RpcCannotSupport,
    rpc_const.RPC_S_NO_CONTEXT_AVAILABLE: RpcNoContextAvailable,
}


def rpc_exception(code):
    ex = _RPC_EX_LOOKUP.get(code, RpcUnknown)
    return ex(code)
