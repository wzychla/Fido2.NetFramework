using Fido2NetLib;
using Fido2NetLib.Objects;
using Fido2NetLib.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace fido2_net_lib.Test
{
    [TestClass]
    public class CredentialPublicKeyTests
    {
        [TestMethod]
        [DataRow( "1.3.132.0.10", COSE.Algorithm.ES256K )] // secP256k1
        [DataRow( "1.2.840.10045.3.1.7", COSE.Algorithm.ES256 )]  // P256
        [DataRow( "1.3.132.0.34", COSE.Algorithm.ES384 )]  // P384
        [DataRow( "1.3.132.0.35", COSE.Algorithm.ES512 )]  // P512
        public void CanUseECCurves( string oid, COSE.Algorithm alg )
        {
            byte[] signedData = RandomNumberHelper.GetBytes( 64 );

            using ( var ecDsa = ECDsa.Create( ECCurve.CreateFromValue( oid ) ) )
            {

                var signature = SignatureHelper.EcDsaSigFromSig(ecDsa.SignData(signedData, CryptoUtils.HashAlgFromCOSEAlg(alg)), ecDsa.KeySize);

                var credentialPublicKey = new CredentialPublicKey(ecDsa, alg);

                using ( var decodedPublicKey = credentialPublicKey.CreateECDsa() )
                {

                    var decodedEcDsaParams = decodedPublicKey.ExportParameters(false);

                    // NOTES
                    // - the oid.value is not set for secP256k1
                    // - macOS does not support the secP256k1 curve

                    if ( decodedEcDsaParams.Curve.Oid?.Value != null )
                    {
                        Assert.AreEqual( oid, decodedEcDsaParams.Curve.Oid.Value );
                    }

                    Assert.IsTrue( credentialPublicKey.Verify( signedData, signature ) );
                }
            }
        }
    }
}