﻿using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Fido2NetLib.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Test.Attestation
{
    [TestClass]

    public class Packed : Fido2Tests.Attestation
    {
        public Packed()
        {
            _attestationObject = new CborMap { { "fmt", "packed" } };
        }

        [TestMethod]
        public async Task TestSelf()
        {
            foreach ( var (type, alg, crv) in Fido2Tests._validCOSEParameters )
            {
                var signature = SignData(type, alg, crv);

                _attestationObject.Set( "attStmt", new CborMap {
                    { "alg", alg },
                    { "sig", signature }
                } );

                var res = await MakeAttestationResponseAsync();

                Assert.AreEqual( string.Empty, res.ErrorMessage );
                Assert.AreEqual( "ok", res.Status );
                Assert.AreEqual( _aaguid, res.Result.AaGuid );
                Assert.AreEqual( _signCount, res.Result.SignCount );
                Assert.AreEqual( "packed", res.Result.AttestationFormat );
                CollectionAssert.AreEqual( _credentialID, res.Result.Id );
                Assert.IsNull( res.Result.ErrorMessage );
                CollectionAssert.AreEqual( _credentialPublicKey.GetBytes(), res.Result.PublicKey );
                Assert.IsNull( res.Result.Status );
                Assert.AreEqual( "Test User", res.Result.User.DisplayName );
                CollectionAssert.AreEqual( Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id );
                Assert.AreEqual( "testuser", res.Result.User.Name );
                _attestationObject = new CborMap { { "fmt", "packed" } };
            }
        }

        [TestMethod]
        public async Task TestSelfAlgMismatch()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];

            byte[] signature = SignData(type, alg, curve);

            _attestationObject.Add( "attStmt", new CborMap {
                { "alg", COSE.Algorithm.ES384 },
                { "sig", signature }
            } );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Algorithm mismatch between credential public key and authenticator data in self attestation statement", ex.Message );
        }

        [TestMethod]
        public async Task TestSelfBadSig()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap {
                { "alg", alg },
                { "sig", new byte[] { 0x30, 0x45, 0x02, 0x20, 0x11, 0x9b, 0x6f, 0xa8, 0x1c, 0xe1, 0x75, 0x9e, 0xbe, 0xf1, 0x52, 0xa6, 0x99, 0x40, 0x5e, 0xd6, 0x6a, 0xcc, 0x01, 0x33, 0x65, 0x18, 0x05, 0x00, 0x96, 0x28, 0x29, 0xbe, 0x85, 0x57, 0xb7, 0x1d, 0x02, 0x21, 0x00, 0x94, 0x50, 0x1d, 0xf1, 0x90, 0x03, 0xa4, 0x4d, 0xa4, 0xdf, 0x9f, 0xbb, 0xb5, 0xe4, 0xce, 0x91, 0x6b, 0xc3, 0x90, 0xe8, 0x38, 0x99, 0x66, 0x4f, 0xa5, 0xc4, 0x0c, 0xf3, 0xed, 0xe3, 0xda, 0x83 } }
            } );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Failed to validate signature", ex.Message );
        }

        [TestMethod]
        public async Task TestMissingAlg()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap { { "sig", signature } } );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid packed attestation algorithm", ex.Message );
        }

        [TestMethod]
        public async Task TestEcdaaKeyIdPresent()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap {
                { "alg", alg },
                { "sig", signature },
                { "ecdaaKeyId", signature }
            } );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.UnimplementedAlgorithm, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.UnimplementedAlgorithm_Ecdaa_Packed, ex.Message );
        }

        [TestMethod]
        public async Task TestEmptyAttStmt()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap { } );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Attestation format packed must have attestation statement", ex.Message );
        }

        [TestMethod]
        public async Task TestAlgNaN()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap {
            { "alg", "invalid alg" },
            { "sig", signature }
        } );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid packed attestation algorithm", ex.Message );
        }

        [TestMethod]
        public async Task TestSigNull()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap {
            { "alg", alg },
            { "sig", CborNull.Instance }
        } );

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

            Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
            Assert.AreEqual( "Invalid packed attestation signature", ex.Message );
        }

        [TestMethod]
        public void TestSigNotByteString()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap {
            { "alg", alg },
            { "sig", "walrus" }
        } );
            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Invalid packed attestation signature", ex.Result.Message );
        }

        [TestMethod]
        public async Task TestSigByteStringZeroLen()
        {
            var (type, alg, crv) = Fido2Tests._validCOSEParameters[0];
            var signature = SignData(type, alg, crv);
            _attestationObject.Add( "attStmt", new CborMap {
            { "alg", alg },
            { "sig", Array.Empty<byte>() }
        } );
            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
            Assert.AreEqual( "Invalid packed attestation signature", ex.Message );
        }

        [TestMethod]
        public async Task TestFull()
        {
            foreach ( var (type, alg, curve) in Fido2Tests._validCOSEParameters )
            {
                if ( type is COSE.KeyType.OKP )
                {
                    return;
                }

                X509Certificate2 attestnCert;
                DateTimeOffset notBefore = DateTimeOffset.UtcNow;
                DateTimeOffset notAfter = notBefore.AddDays(2);
                var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

                Fido2NetLib.Fido2.CredentialMakeResult res = null;

                switch ( type )
                {
                    case COSE.KeyType.EC2:
                        using ( var ecdsaRoot = ECDsa.Create() )
                        {
                            var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                            rootRequest.CertificateExtensions.Add( caExt );

                            ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                            switch ( curve )
                            {
                                case COSE.EllipticCurve.P384:
                                    eCCurve = ECCurve.NamedCurves.nistP384;
                                    break;
                                case COSE.EllipticCurve.P521:
                                    eCCurve = ECCurve.NamedCurves.nistP521;
                                    break;
                                case COSE.EllipticCurve.P256K:
                                    eCCurve = ECCurve.CreateFromFriendlyName( "secP256k1" );
                                    break;
                            }

                            using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                            using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                            {
                                var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                                attRequest.CertificateExtensions.Add( notCAExt );
                                attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                                byte[] serial = RandomNumberHelper.GetBytes(12);

                                using ( X509Certificate2 publicOnly = attRequest.Create(
                                    root,
                                    notBefore,
                                    notAfter,
                                    serial ) )
                                {
                                    attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                                }

                                var x5c = new CborArray {
                                    attestnCert.RawData,
                                    root.RawData
                                };

                                byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                                _attestationObject.Set( "attStmt", new CborMap {
                                    { "alg", alg },
                                    { "sig", signature },
                                    { "x5c", x5c }
                                } );

                                res = await MakeAttestationResponseAsync();
                            }
                        }
                        break;
                    case COSE.KeyType.RSA:
                        using ( RSA rsaRoot = new RSACng() )
                        {
                            var padding = RSASignaturePadding.Pss;

                            switch ( alg ) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                            {
                                case COSE.Algorithm.RS1:
                                case COSE.Algorithm.RS256:
                                case COSE.Algorithm.RS384:
                                case COSE.Algorithm.RS512:
                                    padding = RSASignaturePadding.Pkcs1;
                                    break;
                            }
                            var rootRequest = new CertificateRequest(rootDN, rsaRoot, HashAlgorithmName.SHA256, padding);
                            rootRequest.CertificateExtensions.Add( caExt );

                            using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                            using ( var rsaAtt = new RSACng() )
                            {
                                var attRequest = new CertificateRequest(attDN, rsaAtt, HashAlgorithmName.SHA256, padding);

                                attRequest.CertificateExtensions.Add( notCAExt );
                                attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                                byte[] serial = RandomNumberHelper.GetBytes(12);

                                using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                                {
                                    attestnCert = publicOnly.CopyWithPrivateKey( rsaAtt );
                                }

                                var x5c = new CborArray { attestnCert.RawData, root.RawData };

                                byte[] signature = SignData(type, alg, COSE.EllipticCurve.Reserved, rsa: rsaAtt);

                                _attestationObject.Set( "attStmt", new CborMap {
                                    { "alg", alg },
                                    { "sig", signature },
                                    { "x5c", x5c }
                                } );

                                res = await MakeAttestationResponseAsync();
                            }
                        }
                        break;
                    case COSE.KeyType.OKP:
                        {
                            var avr = new VerifyAssertionResult
                            {
                                CredentialId = new byte[] { 0xf1, 0xd0 },
                                ErrorMessage = string.Empty,
                                Status = "ok",
                            };
                        }
                        break;
                }
                Assert.AreEqual( string.Empty, res.ErrorMessage );
                Assert.AreEqual( "ok", res.Status );
                Assert.AreEqual( _aaguid, res.Result.AaGuid );
                Assert.AreEqual( _signCount, res.Result.SignCount );
                Assert.AreEqual( "packed", res.Result.AttestationFormat );
                CollectionAssert.AreEqual( _credentialID, res.Result.Id );
                Assert.IsNull( res.Result.ErrorMessage );
                CollectionAssert.AreEqual( _credentialPublicKey.GetBytes(), res.Result.PublicKey );
                Assert.IsNull( res.Result.Status );
                Assert.AreEqual( "Test User", res.Result.User.DisplayName );
                CollectionAssert.AreEqual( Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id );
                Assert.AreEqual( "testuser", res.Result.User.Name );
                _attestationObject = new CborMap { { "fmt", "packed" } };
            }
        }

        [TestMethod]
        public void TestFullMissingX5c()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var X5c = new CborArray { attestnCert.RawData, root.RawData };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", CborNull.Instance }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( Fido2ErrorMessages.MalformedX5c_PackedAttestation, ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullX5cNotArray()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var X5c = new CborArray { attestnCert.RawData, root.RawData };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", "boomerang" }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( Fido2ErrorMessages.MalformedX5c_PackedAttestation, ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullX5cCountNotOne()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray { attestnCert.RawData, root.RawData };

                    var signature = SignData(type, alg, COSE.EllipticCurve.Reserved, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature},
                        { "x5c", new CborArray { Array.Empty<byte>(), Array.Empty<byte>() } }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Malformed x5c cert found in packed attestation statement", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullX5cValueNotByteString()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );
                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray { attestnCert.RawData, root.RawData };

                    byte[] signature = SignData(type, alg, COSE.EllipticCurve.Reserved, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", new CborArray { "x" } }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Malformed x5c cert found in packed attestation statement", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullX5cValueZeroLengthByteString()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );
                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray { attestnCert.RawData, root.RawData };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", new CborArray { Array.Empty<byte>() } }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Malformed x5c cert found in packed attestation statement", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullX5cCertExpired()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-7);
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var X5c = new CborArray { attestnCert.RawData, root.RawData };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", X5c }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Packed signing certificate expired or not yet valid", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullX5cCertNotYetValid()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(1);
            DateTimeOffset notAfter = notBefore.AddDays(7);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                    attRequest.CertificateExtensions.Add( notCAExt );
                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray {
                        attestnCert.RawData,
                        root.RawData
                    };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", x5c }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Packed signing certificate expired or not yet valid", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullInvalidAlg()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray { attestnCert.RawData, root.RawData };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", 42 },
                        { "sig", signature },
                        { "x5c", x5c }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<InvalidOperationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Missing or unknown alg 42", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullInvalidSig()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);

                    attRequest.CertificateExtensions.Add( notCAExt );
                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray {
                        attestnCert.RawData,
                        root.RawData
                    };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", new byte[] { 0x30, 0x45, 0x02, 0x20, 0x11, 0x9b, 0x6f, 0xa8, 0x1c, 0xe1, 0x75, 0x9e, 0xbe, 0xf1, 0x52, 0xa6, 0x99, 0x40, 0x5e, 0xd6, 0x6a, 0xcc, 0x01, 0x33, 0x65, 0x18, 0x05, 0x00, 0x96, 0x28, 0x29, 0xbe, 0x85, 0x57, 0xb7, 0x1d, 0x02, 0x21, 0x00, 0x94, 0x50, 0x1d, 0xf1, 0x90, 0x03, 0xa4, 0x4d, 0xa4, 0xdf, 0x9f, 0xbb, 0xb5, 0xe4, 0xce, 0x91, 0x6b, 0xc3, 0x90, 0xe8, 0x38, 0x99, 0x66, 0x4f, 0xa5, 0xc4, 0x0c, 0xf3, 0xed, 0xe3, 0xda, 0x83 } },
                        { "x5c", x5c }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Invalid full packed signature", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullAttCertNotV3()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var rawAttestnCert = attestnCert.RawData;
                    rawAttestnCert[12] = 0x41;

                    var x5c = new CborArray { rawAttestnCert, root.RawData };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature},
                        { "x5c", x5c }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Packed x5c attestation certificate not V3", ex.Result.Message );
                }
            }
        }

        [TestMethod]
        public async Task TestFullAttCertSubject()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Not Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );
                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray {
                        attestnCert.RawData,
                        root.RawData
                    };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", x5c }
                    } );

                    var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

                    Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
                    Assert.AreEqual( Fido2ErrorMessages.InvalidAttestationCertSubject, ex.Message );
                }
            }
        }

        [TestMethod]
        public async Task TestAttCertSubjectCommaAsync()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=\"FIDO2-NET-LIB, Inc.\", C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;

                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray {
                        attestnCert.RawData,
                        root.RawData
                    };

                    var signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", x5c },
                    } );

                    var res = await MakeAttestationResponseAsync();
                    Assert.AreEqual( string.Empty, res.ErrorMessage );
                    Assert.AreEqual( "ok", res.Status );
                }
            }
        }

        [TestMethod]
        public async Task TestFullAttCertAaguidNotMatchAuthdata()
        {
            var (type, alg, curve) = Fido2Tests._validCOSEParameters[0];
            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( ECCurve.NamedCurves.nistP256 ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( notCAExt );

                    var notAsnEncodedAaguid = _asnEncodedAaguid;
                    notAsnEncodedAaguid[3] = 0x42;
                    var notIdFidoGenCeAaguidExt = new X509Extension(oidIdFidoGenCeAaGuid, _asnEncodedAaguid, false);
                    attRequest.CertificateExtensions.Add( notIdFidoGenCeAaguidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create( root, notBefore, notAfter, serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray {
                        attestnCert.RawData,
                        root.RawData
                    };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", x5c }
                    } );

                    var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

                    Assert.AreEqual( Fido2ErrorCode.InvalidAttestation, ex.Code );
                    Assert.AreEqual( "aaguid present in packed attestation cert exts but does not match aaguid from authData", ex.Message );
                }
            }
        }

        [TestMethod]
        public void TestFullAttCertCAFlagSet()
        {
            (COSE.KeyType type, COSE.Algorithm alg, COSE.EllipticCurve curve) = Fido2Tests._validCOSEParameters[0];

            X509Certificate2 attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=Authenticator Attestation, O=FIDO2-NET-LIB, C=US");

            using ( var ecdsaRoot = ECDsa.Create() )
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add( caExt );

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using ( X509Certificate2 root = rootRequest.CreateSelfSigned( notBefore, notAfter ) )
                using ( var ecdsaAtt = ECDsa.Create( eCCurve ) )
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add( caExt );

                    attRequest.CertificateExtensions.Add( idFidoGenCeAaGuidExt );

                    byte[] serial = RandomNumberHelper.GetBytes(12);

                    using ( X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial ) )
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey( ecdsaAtt );
                    }

                    var x5c = new CborArray {
                        attestnCert.RawData,
                        root.RawData
                    };

                    byte[] signature = SignData(type, alg, curve, ecdsa: ecdsaAtt);

                    _attestationObject.Add( "attStmt", new CborMap {
                        { "alg", alg },
                        { "sig", signature },
                        { "x5c", x5c }
                    } );

                    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());
                    Assert.AreEqual( "Attestation certificate has CA cert flag present", ex.Result.Message );
                }
            }
        }
    }
}