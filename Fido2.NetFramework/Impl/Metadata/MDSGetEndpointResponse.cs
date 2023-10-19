using Newtonsoft.Json;

namespace Fido2NetLib
{

    public sealed class MDSGetEndpointResponse
    {
        [JsonConstructor]
        public MDSGetEndpointResponse( string status, string[] result )
        {
            Status = status;
            Result = result;
        }

        [JsonProperty( "status" )]
        public string Status { get; }

        [JsonProperty( "result" )]
        public string[] Result { get; }
    }
}