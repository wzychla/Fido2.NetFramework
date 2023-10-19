﻿using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{

    /// <summary>
    /// PublicKeyCredentialType.
    /// https://www.w3.org/TR/webauthn-2/#enum-credentialType
    /// </summary>
    [JsonConverter( typeof( FidoEnumConverter<PublicKeyCredentialType> ) )]
    public enum PublicKeyCredentialType
    {
        [EnumMember(Value = "public-key")]
        PublicKey,

        [EnumMember(Value = "invalid")]
        Invalid
    }
}