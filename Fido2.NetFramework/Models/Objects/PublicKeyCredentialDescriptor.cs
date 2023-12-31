﻿using System;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// This object contains the attributes that are specified by a caller when referring to a public key credential as an input parameter to the create() or get() methods. It mirrors the fields of the PublicKeyCredential object returned by the latter methods.
    /// Lazy implementation of https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
    /// todo: Should add validation of values as specified in spec
    /// </summary>
    public sealed class PublicKeyCredentialDescriptor
    {
        public PublicKeyCredentialDescriptor( byte[] id )
            : this( PublicKeyCredentialType.PublicKey, id, null ) { }

        [JsonConstructor]
        public PublicKeyCredentialDescriptor( PublicKeyCredentialType type, byte[] id, AuthenticatorTransport[] transports = null )
        {
            Type = type;
            Id = id;
            Transports = transports;
        }

        /// <summary>
        /// This member contains the type of the public key credential the caller is referring to.
        /// </summary>
        [JsonProperty( "type" )]
        public PublicKeyCredentialType Type { get; }

        /// <summary>
        /// This member contains the credential ID of the public key credential the caller is referring to.
        /// </summary>
        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "id" )]
        public byte[] Id { get; }

        /// <summary>
        /// This OPTIONAL member contains a hint as to how the client might communicate with the managing authenticator of the public key credential the caller is referring to.
        /// </summary>
        [JsonProperty( "transports" )]
        
        public AuthenticatorTransport[] Transports { get; }
    }
}