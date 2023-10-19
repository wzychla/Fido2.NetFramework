using System.Collections.Generic;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{

    /// <summary>
    /// This is a dictionary containing the PRF extension input values
    /// </summary>
    public sealed class AuthenticationExtensionsPRFInputs
    {
        /// <summary>
        /// Inputs on which to evaluate PRF.
        /// https://w3c.github.io/webauthn/#dom-authenticationextensionsprfinputs-eval
        /// </summary>
        [JsonProperty( "eval" )]
        public AuthenticationExtensionsPRFValues Eval { get; set; }
        /// <summary>
        /// A record mapping base64url encoded credential IDs to PRF inputs to evaluate for that credential.
        /// https://w3c.github.io/webauthn/#dom-authenticationextensionsprfinputs-evalbycredential
        /// </summary>
        [JsonProperty( "evalByCredential" )]
        
        public KeyValuePair<string, AuthenticationExtensionsPRFValues>? EvalByCredential { get; set; }
    }
}