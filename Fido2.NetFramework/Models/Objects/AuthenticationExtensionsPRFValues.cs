using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{

    /// <summary>
    /// Evaluated PRF values.
    /// </summary>
    public sealed class AuthenticationExtensionsPRFValues
    {
        /// <summary>
        /// salt1 value to the PRF evaluation.
        /// </summary>
        [JsonProperty( "first" )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] First { get; set; }
        /// <summary>
        /// salt2 value to the PRF evaluation.
        /// </summary>
        [JsonProperty( "second" )]
        [JsonConverter( typeof( Base64UrlConverter ) )]
        
        public byte[] Second { get; set; }
    }

}