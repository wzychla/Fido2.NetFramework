using Fido2NetLib.Objects;
using System;
using System.Collections.Generic;
using System.Collections;
using Newtonsoft.Json;
using static Fido2NetLib.Objects.COSE;

namespace Fido2NetLib.Serialization
{
    /// <summary>
    /// https://github.com/dotnet/runtime/issues/83392
    /// https://learn.microsoft.com/pl-pl/dotnet/csharp/language-reference/configure-language-version
    /// </summary>

    //[JsonSerializable( typeof( AssertionOptions ) )]
    //[JsonSerializable( typeof( AuthenticatorAssertionRawResponse ) )]
    //[JsonSerializable( typeof( MetadataBLOBPayload ) )]
    //[JsonSerializable( typeof( CredentialCreateOptions ) )]
    //[JsonSerializable( typeof( MetadataStatement ) )]
    public class FidoModelSerializerContext // : JsonSerializerContext
    {
        public JsonSerializerSettings AssertionOptions
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };                    
            }
        }

        public JsonSerializerSettings CredentialCreateOptions
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
            }
        }

        public JsonSerializerSettings MetadataBLOBPayload
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
            }
        }

        public JsonSerializerSettings MetadataStatement
        {
            get
            {
                return new JsonSerializerSettings()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
            }
        }

        public static FidoModelSerializerContext Default
        {
            get
            {
                return new FidoModelSerializerContext();
            }
        }
    }
}