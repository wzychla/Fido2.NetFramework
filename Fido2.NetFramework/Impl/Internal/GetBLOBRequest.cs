using Newtonsoft.Json;

namespace Fido2NetLib.Internal
{

    public readonly struct GetBLOBRequest
    {
        [JsonConstructor]
        public GetBLOBRequest( string endpoint )
        {
            Endpoint = endpoint;
        }

        [JsonProperty( "endpoint" )]
        public string Endpoint { get; }
    }
}