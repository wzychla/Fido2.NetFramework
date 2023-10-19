using Newtonsoft.Json;

using Fido2NetLib.Objects;

namespace Fido2NetLib
{

    /// <summary>
    /// Transport class for AssertionResponse
    /// </summary>
    public class AuthenticatorAssertionRawResponse
    {
        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "id" )]
        public byte[] Id { get; set; }

        // might be wrong to base64url encode this...
        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "rawId" )]
        public byte[] RawId { get; set; }

        [JsonProperty( "response" )]
        public AssertionResponse Response { get; set; }

        [JsonProperty( "type" )]
        public PublicKeyCredentialType? Type { get; set; }

        [JsonProperty( "extensions" )]
        public AuthenticationExtensionsClientOutputs Extensions { get; set; }

        public class AssertionResponse
        {
            [JsonConverter( typeof( Base64UrlConverter ) )]
            [JsonProperty( "authenticatorData" )]
            public byte[] AuthenticatorData { get; set; }

            [JsonConverter( typeof( Base64UrlConverter ) )]
            [JsonProperty( "signature" )]
            public byte[] Signature { get; set; }

            [JsonConverter( typeof( Base64UrlConverter ) )]
            [JsonProperty( "clientDataJSON" )]
            public byte[] ClientDataJson { get; set; }

            [JsonProperty( "userHandle" )]
            [JsonConverter( typeof( Base64UrlConverter ) )]
            public byte[] UserHandle { get; set; }

            [JsonProperty( "attestationObject" )]
            [JsonConverter( typeof( Base64UrlConverter ) )]
            public byte[] AttestationObject { get; set; }
        }
    }
}