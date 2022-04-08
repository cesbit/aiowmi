from .uuid import uuid_to_bin, uuid_ver_to_bin


CLSID_IWbemLevel1Login =\
    uuid_to_bin('8BC3F05E-D86B-11D0-A075-00C04FB68820')

CLSID_ActivationPropertiesIn =\
    uuid_to_bin('00000338-0000-0000-c000-000000000046')

CLSID_InstantiationInfo =\
    uuid_to_bin('000001ab-0000-0000-c000-000000000046')

CLSID_ActivationContextInfo =\
    uuid_to_bin('000001a5-0000-0000-c000-000000000046')

CLSID_ServerLocationInfo =\
    uuid_to_bin('000001a4-0000-0000-c000-000000000046')

CLSID_ScmRequestInfo =\
    uuid_to_bin('000001aa-0000-0000-c000-000000000046')

IID_IWbemLevel1Login =\
    uuid_ver_to_bin('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0')

IID_IWbemServices =\
    uuid_ver_to_bin('9556DC99-828C-11CF-A37E-00AA003240C7', '0.0')

IID_IRemoteSCMActivator =\
    uuid_ver_to_bin('000001A0-0000-0000-C000-000000000046', '0.0')

IID_IActivationPropertiesIn =\
    uuid_ver_to_bin('000001A2-0000-0000-C000-000000000046', '0.0')

IID_IRemUnknown_str = '00000131-0000-0000-C000-000000000046'

IID_IRemUnknown =\
    uuid_ver_to_bin(IID_IRemUnknown_str, '0.0')

IID_IRemUnknown2 =\
    uuid_ver_to_bin('00000143-0000-0000-C000-000000000046', '0.0')

IID_IWbemFetchSmartEnum_str = '1C1C45EE-4395-11d2-B60B-00104B703EFD'

IID_IWbemFetchSmartEnum_bin = uuid_to_bin(IID_IWbemFetchSmartEnum_str)

IID_IWbemFetchSmartEnum =\
    uuid_ver_to_bin(IID_IWbemFetchSmartEnum_str, '0.0')

IID_IWbemWCOSmartEnum =\
    uuid_ver_to_bin('423EC01E-2E35-11d2-B604-00104B703EFD', '0.0')

NDR_TransferSyntaxIdentifier =\
    uuid_ver_to_bin('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


# 2.2.18 OBJREF
FLAGS_OBJREF_STANDARD = 0x00000001
FLAGS_OBJREF_HANDLER = 0x00000002
FLAGS_OBJREF_CUSTOM = 0x00000004
FLAGS_OBJREF_EXTENDED = 0x00000008


# CLSID_ActivationPropertiesIn  = \
#    string_to_bin('00000338-0000-0000-c000-000000000046')
# CLSID_ActivationPropertiesOut = \
#    string_to_bin('00000339-0000-0000-c000-000000000046')
# CLSID_CONTEXT_EXTENSION       = \
#    string_to_bin('00000334-0000-0000-c000-000000000046')
# CLSID_ContextMarshaler        = \
#    string_to_bin('0000033b-0000-0000-c000-000000000046')
# CLSID_ERROR_EXTENSION         = \
#    string_to_bin('0000031c-0000-0000-c000-000000000046')
# CLSID_ErrorObject             = \
#    string_to_bin('0000031b-0000-0000-c000-000000000046')
# CLSID_InstanceInfo            = \
#    string_to_bin('000001ad-0000-0000-c000-000000000046')
# CLSID_PropsOutInfo            = \
#    string_to_bin('00000339-0000-0000-c000-000000000046')
# CLSID_ScmReplyInfo            = \
#    string_to_bin('000001b6-0000-0000-c000-000000000046')
# CLSID_SecurityInfo            = \
#    string_to_bin('000001a6-0000-0000-c000-000000000046')
# CLSID_SpecialSystemProperties = \
#    string_to_bin('000001b9-0000-0000-c000-000000000046')
# IID_IActivation               = \
#    uuidtup_to_bin(('4d9f4ab8-7d1c-11cf-861e-0020af6e7c57','0.0'))
# IID_IActivationPropertiesOut  = \
#    uuidtup_to_bin(('000001A3-0000-0000-C000-000000000046','0.0'))
# IID_IContext                  = \
#    uuidtup_to_bin(('000001c0-0000-0000-C000-000000000046','0.0'))
# IID_IObjectExporter           = \
#    uuidtup_to_bin(('99fcfec4-5260-101b-bbcb-00aa0021347a','0.0'))
# IID_IRemoteSCMActivator       = \
#    uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046','0.0'))
# IID_IUnknown                  = \
#    uuidtup_to_bin(('00000000-0000-0000-C000-000000000046','0.0'))
# IID_IClassFactory             = \
#    uuidtup_to_bin(('00000001-0000-0000-C000-000000000046','0.0'))
