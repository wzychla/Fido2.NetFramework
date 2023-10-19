namespace Fido2NetLib.Objects
{

    using System;
    using Newtonsoft.Json;

    public sealed class AuthenticationExtensionsDevicePublicKeyInputs
    {
        [JsonProperty( "attestation" )]
        public string Attestation { get; set; } = "none";

        [JsonProperty( "attestationFormats" )]
        public string[] AttestationFormats { get; set; } = Array.Empty<string>();
    }
}