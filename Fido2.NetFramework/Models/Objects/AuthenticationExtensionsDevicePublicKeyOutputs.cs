namespace Fido2NetLib.Objects
{

    using Newtonsoft.Json;

    public sealed class AuthenticationExtensionsDevicePublicKeyOutputs
    {
        [JsonConstructor]
        public AuthenticationExtensionsDevicePublicKeyOutputs( byte[] authenticatorOutput, byte[] signature )
        {
            AuthenticatorOutput = authenticatorOutput;
            Signature = signature;
        }

        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "authenticatorOutput" )]
        public byte[] AuthenticatorOutput { get; }

        [JsonConverter( typeof( Base64UrlConverter ) )]
        [JsonProperty( "signature" )]
        public byte[] Signature { get; }
    }
}