using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System.Threading.Tasks;

namespace Test.Attestation
{
    [TestClass]
    public class None : Fido2Tests.Attestation
    {
        public None()
        {
            _attestationObject = new CborMap { { "fmt", "none" } };
        }

        [TestMethod]
        public async Task TestNone()
        {
            foreach ( var (keyType, alg, crv) in Fido2Tests._validCOSEParameters )
            {
                _attestationObject.Add( "attStmt", new CborMap() );
                _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey( (keyType, alg, crv) );
                Fido2NetLib.Fido2.CredentialMakeResult res;

                res = await MakeAttestationResponseAsync();

                Assert.AreEqual( string.Empty, res.ErrorMessage );
                Assert.AreEqual( "ok", res.Status );
                Assert.AreEqual( _aaguid, res.Result.AaGuid );
                Assert.AreEqual( _signCount, res.Result.SignCount );
                Assert.AreEqual( "none", res.Result.AttestationFormat );
                CollectionAssert.AreEqual( _credentialID, res.Result.Id );
                Assert.IsNull( res.Result.ErrorMessage );
                CollectionAssert.AreEqual( _credentialPublicKey.GetBytes(), res.Result.PublicKey );
                Assert.IsNull( res.Result.Status );
                Assert.AreEqual( "Test User", res.Result.User.DisplayName );
                CollectionAssert.AreEqual( Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id );
                Assert.AreEqual( "testuser", res.Result.User.Name );
                _attestationObject = new CborMap { { "fmt", "none" } };
            }
        }

        [TestMethod]
        public async Task TestNoneWithAttStmt()
        {
            _attestationObject.Add( "attStmt", new CborMap { { "foo", "bar" } } );
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey( Fido2Tests._validCOSEParameters[0] );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Attestation format none should have no attestation statement", ex.Message );
        }
    }
}