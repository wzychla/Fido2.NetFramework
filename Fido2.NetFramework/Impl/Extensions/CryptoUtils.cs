using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{

    public static class CryptoUtils
    {
        public static byte[] HashData256( ReadOnlySpan<byte> data )
        {
            return HashData( HashAlgorithmName.SHA256, data );
        }

        public static byte[] HashData( HashAlgorithmName hashName, ReadOnlySpan<byte> data )
        {
            switch (hashName.Name)
            {
                case "SHA1":
                    using ( var sha = SHA1.Create() )
                    {
                        return sha.ComputeHash( data.ToArray() );
                    };
                case "SHA256":
                case "HS256":
                case "RS256":
                case "ES256":
                case "PS256":
                    using ( var sha = SHA256.Create() )
                    {
                        return sha.ComputeHash( data.ToArray() );
                    };
                case "SHA384":
                case "HS384":
                case "RS384":
                case "ES384":
                case "PS384":
                    using ( var sha = SHA384.Create() )
                    {
                        return sha.ComputeHash( data.ToArray() );
                    };
                case "SHA512":
                case "HS512":
                case "RS512":
                case "ES512":
                case "PS512":
                    using ( var sha = SHA512.Create() )
                    {
                        return sha.ComputeHash( data.ToArray() );
                    };
                default: throw new ArgumentOutOfRangeException( nameof( hashName ) );
            };
        }

        public static HashAlgorithmName HashAlgFromCOSEAlg( COSE.Algorithm alg )
        {
            switch ( alg )
            {
                case COSE.Algorithm.RS1: return HashAlgorithmName.SHA1;
                case COSE.Algorithm.ES256: return HashAlgorithmName.SHA256;
                case COSE.Algorithm.ES384: return HashAlgorithmName.SHA384;
                case COSE.Algorithm.ES512: return HashAlgorithmName.SHA512;
                case COSE.Algorithm.PS256: return HashAlgorithmName.SHA256;
                case COSE.Algorithm.PS384: return HashAlgorithmName.SHA384;
                case COSE.Algorithm.PS512: return HashAlgorithmName.SHA512;
                case COSE.Algorithm.RS256: return HashAlgorithmName.SHA256;
                case COSE.Algorithm.RS384: return HashAlgorithmName.SHA384;
                case COSE.Algorithm.RS512: return HashAlgorithmName.SHA512;
                case COSE.Algorithm.ES256K: return HashAlgorithmName.SHA256;
                case (COSE.Algorithm)4: return HashAlgorithmName.SHA1;
                case (COSE.Algorithm)11: return HashAlgorithmName.SHA256;
                case (COSE.Algorithm)12: return HashAlgorithmName.SHA384;
                case (COSE.Algorithm)13: return HashAlgorithmName.SHA512;
                case COSE.Algorithm.EdDSA: return HashAlgorithmName.SHA512;
                default: throw new Fido2VerificationException( Fido2ErrorMessages.InvalidCoseAlgorithmValue );
            };
        }

        public static bool ValidateTrustChain( X509Certificate2[] trustPath, X509Certificate2[] attestationRootCertificates )
        {
            // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-attestationRootCertificates

            // Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
            // Multiple certificates might be used for different batches of the same model.
            // The array does not represent a certificate chain, but only the trust anchor of that chain.
            // A trust anchor can be a root certificate, an intermediate CA certificate or even the attestation certificate itself.

            // Let's check the simplest case first.  If subject and issuer are the same, and the attestation cert is in the list, that's all the validation we need
            if ( trustPath.Length == 1 && trustPath[0].Subject.Equals( trustPath[0].Issuer, StringComparison.Ordinal ) )
            {
                foreach ( X509Certificate2 cert in attestationRootCertificates )
                {
                    if ( cert.Thumbprint.Equals( trustPath[0].Thumbprint, StringComparison.Ordinal ) )
                    {
                        return true;
                    }
                }
                return false;
            }

            // If the attestation cert is not self signed, we will need to build a chain
            var chain = new X509Chain();

            // Put all potential trust anchors into extra store
            chain.ChainPolicy.ExtraStore.AddRange( attestationRootCertificates );

            // We don't know the root here, so allow unknown root, and turn off revocation checking
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            // trustPath[0] is the attestation cert, if there are more in the array than just that, add those to the extra store as well, but skip attestation cert
            if ( trustPath.Length > 1 )
            {
                foreach ( X509Certificate2 cert in trustPath.Skip( 1 ) ) // skip attestation cert
                {
                    chain.ChainPolicy.ExtraStore.Add( cert );
                }
            }

            // try to build a chain with what we've got
            if ( chain.Build( trustPath[0] ) )
            {
                // if that validated, we should have a root for this chain now, add it to the custom trust store
                chain.ChainPolicy.ExtraStore.Clear();
                chain.ChainPolicy.ExtraStore.Add( chain.ChainElements[chain.ChainElements.Count-1].Certificate );

                // explicitly trust the custom root we just added
                //chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

                // if the attestation cert has a CDP extension, go ahead and turn on online revocation checking
                if ( !string.IsNullOrEmpty( CDPFromCertificateExts( trustPath[0].Extensions ) ) )
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;

                // don't allow unknown root now that we have a custom root
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                // now, verify chain again with all checks turned on
                if ( chain.Build( trustPath[0] ) )
                {
                    // if the chain validates, make sure one of the attestation root certificates is one of the chain elements
                    foreach ( X509Certificate2 attestationRootCertificate in attestationRootCertificates )
                    {
                        // skip the first element, as that is the attestation cert
                        if ( chain.ChainElements
                            .OfType<X509ChainElement>()
                            .Skip( 1 )
                            .Any( x => x.Certificate.Thumbprint.Equals( attestationRootCertificate.Thumbprint, StringComparison.Ordinal ) ) )
                            return true;
                    }
                }
            }

            return false;
        }

        public static byte[] SigFromEcDsaSig( byte[] ecDsaSig, int keySize )
        {
            var decoded = Asn1Element.Decode(ecDsaSig);
            var r = decoded[0].GetIntegerBytes();
            var s = decoded[1].GetIntegerBytes();

            // .NET requires IEEE P-1363 fixed size unsigned big endian values for R and S
            // ASN.1 requires storing positive integer values with any leading 0s removed
            // Convert ASN.1 format to IEEE P-1363 format 
            // determine coefficient size 

            // common coefficient sizes include: 32, 48, and 64
            var coefficientSize = (int)Math.Ceiling((decimal)keySize / 8);

            // Create buffer to copy R into 
            Span<byte> p1363R = coefficientSize <= 64
            ? stackalloc byte[coefficientSize]
            : new byte[coefficientSize];

            if ( 0x0 == r[0] && ( r[1] & ( 1 << 7 ) ) != 0 )
            {
                r.Slice( 1 ).CopyTo( p1363R.Slice( coefficientSize - r.Length + 1 ) );
            }
            else
            {
                r.CopyTo( p1363R.Slice( coefficientSize - r.Length ) );
            }

            // Create byte array to copy S into 
            Span<byte> p1363S = coefficientSize <= 64
            ? stackalloc byte[coefficientSize]
            : new byte[coefficientSize];

            if ( 0x0 == s[0] && ( s[1] & ( 1 << 7 ) ) != 0 )
            {
                s.Slice( 1 ).CopyTo( p1363S.Slice( coefficientSize - s.Length + 1 ) );
            }
            else
            {
                s.CopyTo( p1363S.Slice( coefficientSize - s.Length ) );
            }

            // Concatenate R + S coordinates and return the raw signature
            return DataHelper.Concat( p1363R, p1363S );
        }

        public static string CDPFromCertificateExts( X509ExtensionCollection exts )
        {
            var cdp = "";
            foreach ( var ext in exts )
            {
                if ( ext.Oid?.Value is "2.5.29.31" ) // id-ce-CRLDistributionPoints
                {
                    var asnData = Asn1Element.Decode(ext.RawData);

                    var el = asnData[0][0][0][0];

                    cdp = Encoding.ASCII.GetString( el.GetOctetString( el.Tag ) );
                }
            }
            return cdp;
        }

        public static bool IsCertInCRL( byte[] crl, X509Certificate2 cert )
        {
            var asnData = Asn1Element.Decode(crl);

            if ( 7 > asnData[0].Sequence.Count )
                return false; // empty CRL

            // Certificate users MUST be able to handle serialNumber values up to 20 octets.

            var certificateSerialNumber = cert.GetSerialNumber().ToArray(); // defensively copy

            Array.Reverse( certificateSerialNumber ); // convert to big-endian order

            var revokedAsnSequence = asnData[0][5].Sequence;

            for ( int i = 0; i < revokedAsnSequence.Count; i++ )
            {
                ReadOnlySpan<byte> revokedSerialNumber = revokedAsnSequence[i][0].GetIntegerBytes();

                if ( revokedSerialNumber.SequenceEqual( certificateSerialNumber ) )
                {
                    return true;
                }
            }

            return false;
        }
    }
}