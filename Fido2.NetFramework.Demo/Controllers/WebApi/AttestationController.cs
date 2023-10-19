using Fido2NetLib;
using Fido2NetLib.Objects;
using System.Security;
using System.Security.Claims;
using System.Web.Http;
using Fido2.NetFramework.Demo.Code;
using System.Threading.Tasks;
using System;
using System.Web;
using System.Linq;
using System.Web.Security;
using Microsoft.Extensions.DependencyInjection;
using static Fido2NetLib.Fido2;
using System.Collections.Generic;

namespace Fido2.NetFramework.Demo.Controllers.WebApi
{
    public class AttestationController : ApiController
    {
        private IFido2 _fido2;
        private DevelopmentCustomStore _demoStorage;

        public AttestationController()
        {
            _fido2       = Global.ServiceLocator.GetService<IFido2>();
            _demoStorage = Global.ServiceLocator.GetService<DevelopmentCustomStore>();
        }

        #region Attestation (create profile)

        [Authorize]
        [HttpPost]
        [Route( "api/attestation/options" )]
        public IHttpActionResult Attestation_Options()
        {
            try
            {

                if ( string.IsNullOrEmpty( this.User.Identity.Name ) )
                {
                    throw new SecurityException( "No user" );
                }

                var username    = this.User.Identity.Name;
                var displayName = username;

                // 1. Get user from DB by username (in our example, auto create missing users)
                var user = this._demoStorage.GetUser( username );
                if ( user == null )
                {
                    return this.Ok( new CredentialCreateOptions { Status = "error", ErrorMessage = "no user" } );
                }

                // 2. Get user existing keys by username
                var existingKeys = this._demoStorage.GetCredentialsByUser(user).Select(c => new PublicKeyCredentialDescriptor( c.DescriptorId ) ).ToList();

                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    RequireResidentKey      = true,
                    UserVerification        =  Fido2NetLib.Objects.UserVerificationRequirement.Preferred,
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform
                };

                var exts = new AuthenticationExtensionsClientInputs() { };

                var options = 
                    _fido2.RequestNewCredential(
                        user.ToFidoUser(), 
                        existingKeys, 
                        authenticatorSelection,
                        AttestationConveyancePreference.None, 
                        exts);

                // 4. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Current.Session.Add( "fido2.attestationOptions", options.ToJson() ); 

                // 5. return options to client
                return this.Ok( options );
            }
            catch ( Exception e )
            {
                return this.Ok( new CredentialCreateOptions { Status = "error", ErrorMessage = e.Message } );
            }
        }

        [Authorize]
        [HttpPost]
        [Route( "api/attestation/result" )]
        public async Task<IHttpActionResult> Attestation_Result( [FromBody] AuthenticatorAttestationRawResponse attestationResponse )
        {
            try
            {
                // 1. get the options we sent the client
                var jsonOptions = HttpContext.Current.Session["fido2.attestationOptions"] as string;
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                // 2. Create callback so that lib can verify credential id is unique to this user
                IsCredentialIdUniqueToUserAsyncDelegate callback = async (args, cancellationToken) =>
                {
                    var users = this._demoStorage.GetUsersByCredentialId(args.CredentialId);
                    if (users.Count() > 0)
                        return false;

                    return true;
                };

                // 2. Verify and make the credentials
                var success = await _fido2.MakeNewCredentialAsync(
                    attestationResponse, 
                    options, 
                    callback );

                // 3. Store the credentials in db
                this._demoStorage.AddCredentialToUser( 
                    new StoredUser( options.User ), 
                    new StoredCredential
                    {   
                        CredType   = success.Result.Type.ToString(),
                        UserHandle = success.Result.User.Id,
                        AaGuid     = success.Result.AaGuid,
                        //Descriptor = new PublicKeyCredentialDescriptor( success.Result.CredentialId ),
                        DescriptorId = success.Result.Id,
                        PublicKey  = success.Result.PublicKey,
                        RegDate    = DateTime.Now                        
                        /*
                        Id = success.Result.Id,
                        Descriptor = new PublicKeyCredentialDescriptor( success.Result.Id ),
                        PublicKey = success.Result.PublicKey,
                        UserHandle = success.Result.User.Id,
                        SignCount = success.Result.Counter,
                        CredType = success.Result.CredType,
                        RegDate = DateTime.Now,
                        AaGuid = success.Result.AaGuid,
                        Transports = success.Result.Transports,
                        BE = success.Result.BE,
                        BS = success.Result.BS,
                        AttestationObject = success.Result.AttestationObject,
                        AttestationClientDataJSON = success.Result.AttestationClientDataJSON,
                        DevicePublicKeys = new List<byte[]>() { success.Result.DevicePublicKey }
                        */
                    } );

                    // 4. return "ok" to the client
                    return this.Ok( success );
            }
            catch ( Exception e )
            {
                return this.Ok( new CredentialMakeResult( status: "error", errorMessage: e.Message, result: null ) );
            }
        }

        #endregion

        #region Assertion (login)

        [HttpPost]
        [Route( "api/assertion/options" )]
        public IHttpActionResult Assertion_Options()
        {
            try
            {
                // 1. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    //RequireResidentKey      = true,
                    ResidentKey               = ResidentKeyRequirement.Required,
                    UserVerification          =  Fido2NetLib.Objects.UserVerificationRequirement.Required,
                    AuthenticatorAttachment   = AuthenticatorAttachment.CrossPlatform
                };

                var exts = new AuthenticationExtensionsClientInputs() { };

                var options =
                    _fido2.GetAssertionOptions(
                        new List<Fido2NetLib.Objects.PublicKeyCredentialDescriptor>() { },
                        UserVerificationRequirement.Required,
                        exts );

                // 2. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Current.Session.Add( "fido2.assertionOptions", options.ToJson() );

                // 3. return options to client
                return this.Ok( options );
            }
            catch ( Exception e )
            {
                return this.Ok( new CredentialCreateOptions { Status = "error", ErrorMessage = e.Message } );
            }
        }

        [HttpPost]
        [Route( "api/assertion/result" )]
        public async Task<IHttpActionResult> Assertion_Result( [FromBody] AuthenticatorAssertionRawResponse clientResponse )
        {
            try
            {
                // 1. Get the assertion options we sent the client
                var jsonOptions = HttpContext.Current.Session["fido2.assertionOptions"] as string;
                var options = AssertionOptions.FromJson(jsonOptions);

                // 2. Get registered credential from database
                var creds = this._demoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");

                // 3. Get credential counter from database
                var storedCounter = creds.SignatureCounter;

                // 4. Create callback to check if userhandle owns the credentialId
                IsUserHandleOwnerOfCredentialIdAsync callback = async (args, cancellationToken) =>
                {
                    var storedCreds = this._demoStorage.GetCredentialsByUserHandle(args.UserHandle);
                    return storedCreds.Any(c => c.DescriptorId.SequenceEqual(args.CredentialId));
                };

                // 5. Make the assertion
                var res = await _fido2.MakeAssertionAsync(
                    clientResponse, 
                    options, 
                    creds.PublicKey, 
                    new List<byte[]>(),
                    storedCounter,
                    callback );

                if ( res.Status == "ok" )
                {
                    var users = this._demoStorage.GetUsersByCredentialId(res.CredentialId);

                    if ( users.Count() > 0 )
                    {
                        var username = users.First().Name;

                        // create identity
                        var identity = new ClaimsIdentity(
                        new []
                        {
                            new Claim( ClaimTypes.NameIdentifier, Guid.NewGuid().ToString() ),
                            new Claim( ClaimTypes.Name, username )
                        }, "custom" );
                        ClaimsPrincipal principal = new ClaimsPrincipal(identity);

                        FormsAuthentication.SetAuthCookie( username, false );
                    }
                    else
                    {
                        throw new Exception( "no user" );
                    }
                }
                else
                {
                    throw new Exception( "validation failed" );
                }

                // 6. Store the updated counter
                this._demoStorage.UpdateCounter( res.CredentialId, res.SignCount );

                // 7. return OK to client
                return this.Ok( res );
            }
            catch ( Exception e )
            {
                return this.Ok( new AssertionVerificationResult { Status = "error", ErrorMessage = e.Message } );
            }
        }

        #endregion

    }
}
