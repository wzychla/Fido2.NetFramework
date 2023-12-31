﻿using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Test.Attestation
{

    [TestClass]
    public class AndroidKey : Fido2Tests.Attestation
    {
        public byte[] EncodeAttestationRecord()
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull(); // attestationSecurityLevel
                writer.WriteInteger( 2 ); // keymasterVersion
                writer.WriteNull(); // keymasterSecurityLevel
                writer.WriteOctetString( _clientDataHash ); // attestationChallenge
                writer.WriteOctetString( _credentialID ); // uniqueId
                using ( writer.PushSequence() ) // softwareEnforced
                {
                    writer.WriteNull();
                }
                using ( writer.PushSequence() ) // teeEnforced
                {
                    writer.WriteNull();
                }
            }
            return writer.Encode();
        }

        public AndroidKey()
        {
            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", EncodeAttestationRecord(), false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", COSE.Algorithm.ES256 },
                        { "x5c", X5c },
                        { "sig", signature }
                    } );
                }
            }
        }

        [TestMethod]
        public async Task TestAndroidKey()
        {
            var res = await MakeAttestationResponseAsync();
            Assert.AreEqual( string.Empty, res.ErrorMessage );
            Assert.AreEqual( "ok", res.Status );
            Assert.AreEqual( _aaguid, res.Result.AaGuid );
            Assert.AreEqual( _signCount, res.Result.SignCount );
            Assert.AreEqual( "android-key", res.Result.AttestationFormat );
            CollectionAssert.AreEqual( _credentialID, res.Result.Id );
            Assert.IsNull( res.Result.ErrorMessage );
            CollectionAssert.AreEqual( _credentialPublicKey.GetBytes(), res.Result.PublicKey );
            Assert.IsNull( res.Result.Status );
            Assert.AreEqual( "Test User", res.Result.User.DisplayName );
            CollectionAssert.AreEqual( Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id );
            Assert.AreEqual( "testuser", res.Result.User.Name );
        }

        [TestMethod]
        public async Task TestAndroidKeySigNull()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "sig", CborNull.Instance );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid android-key attestation signature", ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyAttStmtEmpty()
        {
            _attestationObject.Set( "attStmt", new CborMap { } );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Attestation format android-key must have attestation statement", ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeySigNotByteString()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "sig", new CborTextString( "walrus" ) );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid android-key attestation signature", ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeySigByteStringZeroLen()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "sig", new CborByteString( Array.Empty<byte>() ) );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid android-key attestation signature", ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyMissingX5c()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "x5c", CborNull.Instance );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message );
        }
        [TestMethod]
        public async Task TestAndroidKeyX5cNotArray()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "x5c", new CborTextString( "boomerang" ) );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyX5cValueNotByteString()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "x5c", new CborTextString( "x" ) );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyX5cValueZeroLengthByteString()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "x5c", new CborArray { Array.Empty<byte>() } );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.MalformedX5c_AndroidKeyAttestation, ex.Message );
        }

        [TestMethod]
        public void TestAndroidKeyInvalidPublicKey()
        {
            var attestnCert = (byte[])_attestationObject["attStmt"]["x5c"][0];
            attestnCert[0] ^= 0xff;
            var X5c = new CborArray { attestnCert };
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "x5c", X5c );
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.IsTrue( ex.Result.Message.StartsWith( "Failed to extract public key from android key: " ) );
        }

        [TestMethod]
        public async Task TestAndroidKeyMissingAlg()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Remove( "alg" );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid android-key attestation algorithm", ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyAlgNull()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "alg", CborNull.Instance );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid android-key attestation algorithm", ex.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyAlgNaN()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "alg", new CborTextString( "invalid alg" ) );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid android-key attestation algorithm", ex.Message );
        }

        [TestMethod]
        public void TestAndroidKeyAlgNotInMap()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "alg", new CborInteger( -1 ) );
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Unrecognized COSE algorithm value", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeySigNotASN1()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            attStmt.Set( "sig", new CborByteString( new byte[] { 0xf1, 0xd0 } ) );
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Failed to decode android key attestation signature from ASN.1 encoded form", ex.Result.Message );

            var innerException = (AsnContentException)ex.Result.InnerException;
            Assert.AreEqual( "The ASN.1 value is invalid.", innerException.Message );
        }

        [TestMethod]
        public async Task TestAndroidKeyBadSig()
        {
            var attStmt = (CborMap)_attestationObject["attStmt"];
            var sig = (byte[])attStmt["sig"];
            sig[sig.Length-1] ^= 0xff;
            attStmt.Set( "sig", new CborByteString( sig ) );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( Fido2ErrorMessages.InvalidAndroidKeyAttestationSignature, ex.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertMissingAttestationRecordExt()
        {
            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Android key attestation certificate contains no AttestationRecord extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordExtMalformed()
        {
            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", new byte[] { 0x0 }, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var x5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", x5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Malformed android key AttestationRecord extension verifying android key attestation certificate extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordAllApplicationsSoftware()
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull();
                writer.WriteInteger( 2 );
                writer.WriteNull();
                writer.WriteOctetString( _clientDataHash );
                writer.WriteOctetString( _credentialID );
                using ( writer.PushSequence() )
                {
                    using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 600 ) ) )
                    {
                        writer.WriteNull();
                    }
                }
                using ( writer.PushSequence() )
                {
                    writer.WriteNull();
                }
            }
            var attRecord = writer.Encode();

            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", attRecord, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Found all applications field in android key attestation certificate extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordAllApplicationsTee()
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull();
                writer.WriteInteger( 2 );
                writer.WriteNull();
                writer.WriteOctetString( _clientDataHash );
                writer.WriteOctetString( _credentialID );
                using ( writer.PushSequence() )
                {
                    writer.WriteNull();
                }
                using ( writer.PushSequence() )
                {
                    using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 600 ) ) )
                    {
                        writer.WriteNull();
                    }
                }
            }
            var attRecord = writer.Encode();

            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", attRecord, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Found all applications field in android key attestation certificate extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordOriginSoftware()
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull();
                writer.WriteInteger( 2 );
                writer.WriteNull();
                writer.WriteOctetString( _clientDataHash );
                writer.WriteOctetString( _credentialID );
                using ( writer.PushSequence() )
                {
                    using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 702 ) ) )
                    {
                        writer.WriteInteger( 1 );
                    }
                }
                using ( writer.PushSequence() )
                {
                    writer.WriteNull();
                }
            }
            var attRecord = writer.Encode();

            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", attRecord, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordOriginTee()
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull();
                writer.WriteInteger( 2 );
                writer.WriteNull();
                writer.WriteOctetString( _clientDataHash );
                writer.WriteOctetString( _credentialID );
                using ( writer.PushSequence() )
                {
                    writer.WriteNull();
                }
                using ( writer.PushSequence() )
                {
                    using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 702 ) ) )
                    {
                        writer.WriteInteger( 1 );
                    }
                }
            }
            var attRecord = writer.Encode();

            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", attRecord, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Found origin field not set to KM_ORIGIN_GENERATED in android key attestation certificate extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordPurposeSoftware()
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull();
                writer.WriteInteger( 2 );
                writer.WriteNull();
                writer.WriteOctetString( _clientDataHash );
                writer.WriteOctetString( _credentialID );
                using ( writer.PushSequence() )
                {
                    using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 1 ) ) )
                    {
                        using ( writer.PushSetOf() )
                        {
                            writer.WriteInteger( 1 );
                        }
                    }
                }
                using ( writer.PushSequence() )
                {
                    writer.WriteNull();
                }
            }
            var attRecord = writer.Encode();

            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", attRecord, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Result.Message );
        }

        [TestMethod]
        public void TestAndroidKeyX5cCertAttestationRecordPurposeTee()
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() ) // KeyDescription
            {
                writer.WriteInteger( 3 ); // attestationVersion
                writer.WriteNull();
                writer.WriteInteger( 2 );
                writer.WriteNull();
                writer.WriteOctetString( _clientDataHash );
                writer.WriteOctetString( _credentialID );
                using ( writer.PushSequence() )
                {
                    writer.WriteNull();
                }
                using ( writer.PushSequence() )
                {
                    using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 1 ) ) )
                    {
                        using ( writer.PushSetOf() )
                        {
                            writer.WriteInteger( 1 );
                        }
                    }
                }
            }
            var attRecord = writer.Encode();

            _attestationObject = new CborMap { { "fmt", "android-key" } };
            X509Certificate2 attestnCert;
            using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
            {
                var attRequest = new CertificateRequest("CN=AndroidKeyTesting, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US", ecdsaAtt, HashAlgorithmName.SHA256);

                attRequest.CertificateExtensions.Add( new X509Extension( "1.3.6.1.4.1.11129.2.1.17", attRecord, false ) );

                using ( attestnCert = attRequest.CreateSelfSigned( DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays( 2 ) ) )
                {
                    var X5c = new CborArray { attestnCert.RawData };

                    byte[] signature = SignData(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                    { "alg", COSE.Algorithm.ES256 },
                    { "x5c", X5c },
                    { "sig", signature }
                } );
                }
            }
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Found purpose field not set to KM_PURPOSE_SIGN in android key attestation certificate extension", ex.Result.Message );
        }
    }
}