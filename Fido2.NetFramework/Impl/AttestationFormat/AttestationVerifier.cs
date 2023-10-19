using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{

    public abstract class AttestationVerifier
    {
        public (AttestationType, X509Certificate2[]) Verify( CborMap attStmt, AuthenticatorData authenticatorData, byte[] clientDataHash )
        {
            return Verify( new VerifyAttestationRequest( attStmt, authenticatorData, clientDataHash ) );
        }

        public abstract (AttestationType, X509Certificate2[]) Verify( VerifyAttestationRequest request );

        public static AttestationVerifier Create( string formatIdentifier )
        {
            switch ( formatIdentifier )
            {
                case "none": return new None();                        // https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
                case "tpm": return new Tpm();                          // https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
                case "android-key": return new AndroidKey();           // https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
                case "android-safetynet": return new AndroidSafetyNet(); // https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation
                case "fido-u2f": return new FidoU2f();                 // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
                case "packed": return new Packed();                    // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
                case "apple": return new Apple();                      // https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
                case "apple-appattest": return new AppleAppAttest();   // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server  
                default: throw new Fido2VerificationException( Fido2ErrorCode.UnknownAttestationType, $"Unknown attestation type. Was '{formatIdentifier}'" );
            };
        }

        internal static bool IsAttnCertCACert( X509ExtensionCollection exts )
        {
            var ext = exts.OfType<X509Extension>().FirstOrDefault(e => e.Oid?.Value is "2.5.29.19");
            if ( ext is X509BasicConstraintsExtension baseExt )
            {
                return baseExt.CertificateAuthority;
            }

            return true;
        }

        internal static byte[] AaguidFromAttnCertExts( X509ExtensionCollection exts )
        {
            byte[] aaguid = null;
            var ext = exts.OfType<X509Extension>().FirstOrDefault(e => e.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
            if ( ext != null )
            {
                var decodedAaguid = Asn1Element.Decode(ext.RawData);
                decodedAaguid.CheckTag( Asn1Tag.PrimitiveOctetString );
                aaguid = decodedAaguid.GetOctetString();

                // The extension MUST NOT be marked as critical
                if ( ext.Critical )
                    throw new Fido2VerificationException( "extension MUST NOT be marked as critical" );
            }

            return aaguid;
        }

        internal static byte U2FTransportsFromAttnCert( X509ExtensionCollection exts )
        {
            byte u2fTransports = 0;
            var ext = exts.OfType<X509Extension>().FirstOrDefault(e => e.Oid?.Value is "1.3.6.1.4.1.45724.2.1.1"); // id-fido-u2f-ce-transports 
            if ( ext != null )
            {
                var decodedU2fTransports = Asn1Element.Decode(ext.RawData);
                decodedU2fTransports.CheckPrimitive();

                // some certificates seem to have this encoded as an octet string
                // instead of a bit string, attempt to correct
                if ( decodedU2fTransports.Tag == Asn1Tag.PrimitiveOctetString )
                {
                    ext.RawData[0] = (byte)UniversalTagNumber.BitString;
                    decodedU2fTransports = Asn1Element.Decode( ext.RawData );
                }

                decodedU2fTransports.CheckTag( Asn1Tag.PrimitiveBitString );

                u2fTransports = decodedU2fTransports.GetBitString()[0];
            }

            return u2fTransports;
        }
    }
}