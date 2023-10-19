using Newtonsoft.Json;

using Fido2NetLib.Objects;

namespace Fido2NetLib
{

    public sealed class AuthenticatorAttestationRawResponse
    {
        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "id" )]
        public byte[] Id { get; set; }

        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "rawId" )]
        public byte[] RawId { get; set; }

        [JsonProperty( "type" )]
        public PublicKeyCredentialType Type { get; set; } = PublicKeyCredentialType.PublicKey;

        [JsonProperty( "response" )]
        public ResponseData Response { get; set; }

        [JsonProperty( "extensions" )]
        public AuthenticationExtensionsClientOutputs Extensions { get; set; }

        public sealed class ResponseData
        {
            [JsonConverter( typeof( Base64UrlConverter ) )]
            [JsonProperty( "attestationObject" )]
            public byte[] AttestationObject { get; set; }

            [JsonConverter( typeof( Base64UrlConverter ) )]
            [JsonProperty( "clientDataJSON" )]
            public byte[] ClientDataJson { get; set; }
        }
    }
}