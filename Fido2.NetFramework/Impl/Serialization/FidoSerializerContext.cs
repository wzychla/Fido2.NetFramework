using Newtonsoft.Json;

using Fido2NetLib.Internal;

namespace Fido2NetLib.Serialization
{

    //[JsonSerializable( typeof( AuthenticatorResponse ) )]
    //[JsonSerializable( typeof( MDSGetEndpointResponse ) )]
    //[JsonSerializable( typeof( GetBLOBRequest ) )]
    public partial class FidoSerializerContext //: JsonSerializerContext
    {
        public JsonSerializerSettings AuthenticatorResponse
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
            }
        }

        public JsonSerializerSettings MDSGetEndpointResponse
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
            }
        }

        public JsonSerializerSettings GetBLOBRequest
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
            }
        }

        public static FidoSerializerContext Default
        {
            get
            {
                return new FidoSerializerContext();
            }
        }
    }
}