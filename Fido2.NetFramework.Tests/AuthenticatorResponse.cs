using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Fido2NetLib.Serialization;
using Fido2NetLib.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Test
{
    [TestClass]
    public class AuthenticatorResponseTests
    {
        [TestMethod]
        public void CanDeserialize()
        {
            var response = JsonConvert.DeserializeObject<AuthenticatorResponse>("{\"type\":\"webauthn.get\",\"challenge\":\"J4fjxBV-BNywGRJRm8JZ7znvdiZo9NINObNBpnKnJQEOtplTMF0ERuIrzrkeoO-dNMoeMZjhzqfar7eWRANvPeNFPrB5Q6zlS1ZFPf37F3suIwpXi9NCpFA_RlBSiygLmvcIOa57_QHubZQD3cv0UWtRTLslJjmgumphMc7EFN8\",\"origin\":\"https://www.passwordless.dev\"}");

            Assert.AreEqual( "webauthn.get", response.Type );
            CollectionAssert.AreEqual( Base64Url.Decode( "J4fjxBV-BNywGRJRm8JZ7znvdiZo9NINObNBpnKnJQEOtplTMF0ERuIrzrkeoO-dNMoeMZjhzqfar7eWRANvPeNFPrB5Q6zlS1ZFPf37F3suIwpXi9NCpFA_RlBSiygLmvcIOa57_QHubZQD3cv0UWtRTLslJjmgumphMc7EFN8".ToCharArray() ), response.Challenge );
            Assert.AreEqual( "https://www.passwordless.dev", response.Origin );
        }

        [TestMethod]
        [DataRow( "https://www.passwordless.dev", "https://www.passwordless.dev" )]
        [DataRow( "https://www.passwordless.dev:443", "https://www.passwordless.dev:443" )]
        [DataRow( "https://www.passwordless.dev", "https://www.passwordless.dev:443" )]
        [DataRow( "https://www.passwordless.dev:443", "https://www.passwordless.dev" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev:443/foo/bar.html" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev:443/bar/foo.html" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev/bar/foo.html" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "https://www.passwordless.dev" )]
        [DataRow( "ftp://www.passwordless.dev", "ftp://www.passwordless.dev" )]
        [DataRow( "ftp://www.passwordless.dev:8080", "ftp://www.passwordless.dev:8080" )]
        [DataRow( "http://127.0.0.1", "http://127.0.0.1" )]
        [DataRow( "http://localhost", "http://localhost" )]
        [DataRow( "https://127.0.0.1:80", "https://127.0.0.1:80" )]
        [DataRow( "http://localhost:80", "http://localhost:80" )]
        [DataRow( "http://127.0.0.1:443", "http://127.0.0.1:443" )]
        [DataRow( "http://localhost:443", "http://localhost:443" )]
        [DataRow( "android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU", "android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU" )]
        [DataRow( "lorem:ipsum:dolor", "lorem:ipsum:dolor" )]
        [DataRow( "lorem:/ipsum:4321", "lorem:/ipsum:4321" )]
        [DataRow( "lorem://ipsum:1234", "lorem://ipsum:1234" )]
        [DataRow( "lorem://ipsum:9876/sit", "lorem://ipsum:9876/sit" )]
        [DataRow( "foo://bar:321/path/", "foo://bar:321/path/" )]
        [DataRow( "foo://bar:321/path", "foo://bar:321/path" )]
        [DataRow( "http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]" )]
        [DataRow( "http://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]:80" )]
        [DataRow( "https://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]" )]
        [DataRow( "https://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]:443" )]
        public async Task TestAuthenticatorOriginsAsync( string origin, string expectedOrigin )
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = origin;
            var acd = AttestedCredentialData.Parse("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0".FromHexString());
            var authData = new AuthenticatorData(
                CryptoUtils.HashData256(Encoding.UTF8.GetBytes(origin)),
                AuthenticatorFlags.UP | AuthenticatorFlags.AT,
                0,
                acd
            ).ToByteArray();

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp
            });
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>
            {
                PubKeyCredParam.ES256
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes("testuser"),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration()
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { expectedOrigin },
            });

            var result = await lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback);
        }

        [TestMethod]
        [DataRow( "https://www.passwordless.dev", "http://www.passwordless.dev" )]
        [DataRow( "https://www.passwordless.dev:443", "http://www.passwordless.dev:443" )]
        [DataRow( "https://www.passwordless.dev", "http://www.passwordless.dev:443" )]
        [DataRow( "https://www.passwordless.dev:443", "http://www.passwordless.dev" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev:443/foo/bar.html" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev:443/bar/foo.html" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev/bar/foo.html" )]
        [DataRow( "https://www.passwordless.dev:443/foo/bar.html", "http://www.passwordless.dev" )]
        [DataRow( "ftp://www.passwordless.dev", "ftp://www.passwordless.dev:80" )]
        [DataRow( "ftp://www.passwordless.dev:8080", "ftp://www.passwordless.dev:8081" )]
        [DataRow( "https://127.0.0.1", "http://127.0.0.1" )]
        [DataRow( "https://localhost", "http://localhost" )]
        [DataRow( "https://127.0.0.1:80", "https://127.0.0.1:81" )]
        [DataRow( "http://localhost:80", "http://localhost:82" )]
        [DataRow( "http://127.0.0.1:443", "http://127.0.0.1:444" )]
        [DataRow( "http://localhost:443", "http://localhost:444" )]
        [DataRow( "android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU", "android:apk-key-hash:Ae3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU" )]
        [DataRow( "lorem:ipsum:dolor", "lorem:dolor:ipsum" )]
        [DataRow( "lorem:/ipsum:4321", "lorem:/ipsum:4322" )]
        [DataRow( "lorem://ipsum:1234", "lorem://ipsum:1235" )]
        [DataRow( "lorem://ipsum:9876/sit", "lorem://ipsum:9877/sit" )]
        [DataRow( "foo://bar:321/path/", "foo://bar:322/path/" )]
        [DataRow( "foo://bar:321/path", "foo://bar:322/path" )]
        [DataRow( "https://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]" )]
        [DataRow( "https://[0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]:80" )]
        [DataRow( "http://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]" )]
        [DataRow( "http://[0:0:0:0:0:0:0:1]", "https://[0:0:0:0:0:0:0:1]:443" )]
        public void TestAuthenticatorOriginsFail( string origin, string expectedOrigin )
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = origin;
            var acd = AttestedCredentialData.Parse("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0".FromHexString());
            var authData = new AuthenticatorData(
                CryptoUtils.HashData256(Encoding.UTF8.GetBytes(origin)),
                AuthenticatorFlags.UP | AuthenticatorFlags.AT,
                0,
                acd
            ).ToByteArray();
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(true);
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { expectedOrigin },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.IsTrue( ex.Result.Message.StartsWith( "Fully qualified origin" ) );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationRawResponse()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                Type = "webauthn.create",
                Challenge = challenge,
                Origin = "https://www.passwordless.dev",
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = new CborMap().Encode(),
                    ClientDataJson = clientDataJson
                },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = true,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
                    PRF = new AuthenticationExtensionsPRFOutputs
                    {
                        Enabled = true,
                        Results = new AuthenticationExtensionsPRFValues
                        {
                            First = new byte[] { 0xf1, 0xd0 },
                            Second = new byte[] { 0xf1, 0xd0 }
                        }
                    }
                }
            };
            Assert.AreEqual( PublicKeyCredentialType.PublicKey, rawResponse.Type );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, rawResponse.Id );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, rawResponse.RawId );
            CollectionAssert.AreEqual( new byte[] { 0xa0 }, rawResponse.Response.AttestationObject );
            CollectionAssert.AreEqual( clientDataJson, rawResponse.Response.ClientDataJson );
            Assert.IsTrue( rawResponse.Extensions.AppID );
            Assert.IsTrue( rawResponse.Extensions.AuthenticatorSelection );
            CollectionAssert.AreEqual( new string[] { "foo", "bar" }, rawResponse.Extensions.Extensions );
            Assert.AreEqual( "test", rawResponse.Extensions.Example );
            Assert.AreEqual( (ulong)4, rawResponse.Extensions.UserVerificationMethod[0][0] );
            Assert.IsTrue( rawResponse.Extensions.PRF.Enabled );
            CollectionAssert.AreEqual( rawResponse.Extensions.PRF.Results.First, new byte[] { 0xf1, 0xd0 } );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, rawResponse.Extensions.PRF.Results.Second );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationRawResponseNull()
        {
            var ex = Assert.ThrowsException<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(null));

            Assert.AreEqual( "Expected rawResponse, got null", ex.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseNull()
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = null
            };

            var ex = Assert.ThrowsException<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.AreEqual( "Expected rawResponse, got null", ex.Message );
        }

        [TestMethod]
        [DataRow( null )]
        [DataRow( new byte[0] )]
        public void TestAuthenticatorAttestationResponseAttestationObjectNull( byte[] value )
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = value,
                }
            };
            var ex = Assert.ThrowsException<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.AreEqual( "Missing AttestationObject", ex.Message );
        }

        [TestMethod]
        [DataRow( new byte[] { 0x66, 0x6f, 0x6f } )]
        public void TestAuthenticatorAttestationObjectBadCBOR( byte[] value )
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = value,
                }
            };

            var ex = Assert.ThrowsException<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));
            Assert.AreEqual( Fido2ErrorMessages.InvalidAttestationObject, ex.Message );
            Assert.AreEqual( Fido2ErrorCode.InvalidAttestationObject, ex.Code );

            var innerEx = (CborContentException)ex.InnerException;

            Assert.AreEqual( "Declared definite length of CBOR data item exceeds available buffer size.", innerEx.Message );
        }

        [TestMethod]
        [DataRow( new byte[] { 0xa1, 0x63, 0x66, 0x6d, 0x74, 0xf6 } )] // "fmt", null
        [DataRow( new byte[] { 0xa1, 0x63, 0x66, 0x6d, 0x74, 0x18, 0x2a } )] // "fmt", 42
        [DataRow( new byte[] { 0xa1, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xf6 } )] // "attStmt", null
        [DataRow( new byte[] { 0xa1, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74 } )] // "attStmt", "attStmt"
        [DataRow( new byte[] { 0xa1, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0xf6 } )] // "authData", null
        [DataRow( new byte[] { 0xa1, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61 } )] // "authData", "authData"
        public void TestAuthenticatorAttestationObjectMalformed( byte[] value )
        {
            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = value
                }
            };

            var ex = Assert.ThrowsException<Fido2VerificationException>(() => AuthenticatorAttestationResponse.Parse(rawResponse));

            Assert.AreEqual( Fido2ErrorCode.MalformedAttestationObject, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.MalformedAttestationObject, ex.Message );
        }

        [TestMethod]
        public async Task TestAuthenticatorAttestationResponseInvalidType()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                Type = "webauthn.get",
                Challenge = challenge,
                Origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", new AuthenticatorData(new byte[32], default, 0, null, null).ToByteArray() }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( Fido2ErrorMessages.AttestationResponseTypeNotWebAuthnGet, ex.Message );
        }

        [TestMethod]
        [DataRow( null )]
        [DataRow( new byte[0] )]
        public void TestAuthenticatorAttestationResponseInvalidRawId( byte[] value )
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = value,
                RawId = value,
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", new AuthenticatorData(new byte[32], default, 0, null, null).ToByteArray() }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( Fido2ErrorMessages.AttestationResponseIdMissing, ex.Result.Message );
        }

        [TestMethod]
        public async Task TestAuthenticatorAttestationResponseInvalidRawType()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.Invalid,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", new AuthenticatorData(new byte[32], default, 0, null, null).ToByteArray() }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( "AttestationResponse type must be 'public-key'", ex.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseRpidMismatch()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes( "passwordless.dev" )),
            AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( Fido2ErrorCode.InvalidRpidHash, ex.Result.Code );
            Assert.AreEqual( Fido2ErrorMessages.InvalidRpidHash, ex.Result.Message );
        }

        [TestMethod]
        public async Task TestAuthenticatorAttestationResponseNotUserPresentAsync()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),

                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));

            Assert.AreEqual( Fido2ErrorCode.UserPresentFlagNotSet, ex.Code );
            Assert.AreEqual( Fido2ErrorMessages.UserPresentFlagNotSet, ex.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseBackupEligiblePolicyRequired()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User"
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseBackupEligiblePolicyDisallowed()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE,
            0,
            null
        ).ToByteArray();

            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Disallowed,
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseNoAttestedCredentialData()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            null
        ).ToByteArray();

            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( "Attestation flag not set on attestation data", ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseUnknownAttestationType()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var acd = AttestedCredentialData.Parse("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0".FromHexString());
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            acd
        ).ToByteArray();

            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "testing" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( "Unknown attestation type. Was 'testing'", ex.Result.Message );
            Assert.AreEqual( Fido2ErrorCode.UnknownAttestationType, ex.Result.Code );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseNotUniqueCredId()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var acd = AttestedCredentialData.Parse("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0".FromHexString());
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV,
            0,
            acd
        ).ToByteArray();
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Discouraged,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
            {
                return Task.FromResult(false);
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( "CredentialId is not unique to this user", ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAttestationResponseUVRequired()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var acd = AttestedCredentialData.Parse("000000000000000000000000000000000040FE6A3263BE37D101B12E57CA966C002293E419C8CD0106230BC692E8CC771221F1DB115D410F826BDB98AC642EB1AEB5A803D1DBC147EF371CFDB1CEB048CB2CA5010203262001215820A6D109385AC78E5BF03D1C2E0874BE6DBBA40B4F2A5F2F1182456565534F672822582043E1082AF3135B40609379AC474258AAB397B8861DE441B44E83085D1C6BE0D0".FromHexString());
            var authData = new AuthenticatorData(
            CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)),
            AuthenticatorFlags.AT | AuthenticatorFlags.UP,
            0,
            acd
        ).ToByteArray();
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = challenge,
                origin = rp,
            });

            var rawResponse = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Response = new AuthenticatorAttestationRawResponse.ResponseData()
                {
                    AttestationObject = new CborMap {
                    { "fmt", "none" },
                    { "attStmt", new CborMap() },
                    { "authData", authData }
                }.Encode(),
                    ClientDataJson = clientDataJson
                },
            };

            var origChallenge = new CredentialCreateOptions
            {
                Attestation = AttestationConveyancePreference.Direct,
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Required,
                },
                Challenge = challenge,
                ErrorMessage = "",
                PubKeyCredParams = new List<PubKeyCredParam>()
            {
                new PubKeyCredParam(COSE.Algorithm.ES256)
            },
                Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
                Status = "ok",
                User = new Fido2NetLib.Fido2User
                {
                    Name = "testuser",
                    Id = Encoding.UTF8.GetBytes( "testuser" ),
                    DisplayName = "Test User",
                },
                Timeout = 60000,
            };

            IsCredentialIdUniqueToUserAsyncDelegate callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeNewCredentialAsync(rawResponse, origChallenge, callback));
            Assert.AreEqual( "User Verified flag not set in authenticator data and user verification was required", ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionRawResponse()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(new
            {
                Type = "webauthn.get",
                Challenge = challenge,
                Origin = "https://www.passwordless.dev",
            });

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = new byte[] { 0xf1, 0xd0 },
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = true,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                    PRF = new AuthenticationExtensionsPRFOutputs
                    {
                        Enabled = true,
                        Results = new AuthenticationExtensionsPRFValues
                        {
                            First = new byte[] { 0xf1, 0xd0 },
                            Second = new byte[] { 0xf1, 0xd0 }
                        }
                    }
                }
            };
            Assert.AreEqual( PublicKeyCredentialType.PublicKey, assertionResponse.Type );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.Id );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.RawId );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.Response.AuthenticatorData );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.Response.Signature );
            CollectionAssert.AreEqual( clientDataJson, assertionResponse.Response.ClientDataJson );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.Response.UserHandle );
            Assert.IsTrue( assertionResponse.Extensions.AppID );
            Assert.IsTrue( assertionResponse.Extensions.AuthenticatorSelection );
            CollectionAssert.AreEqual( new string[] { "foo", "bar" }, assertionResponse.Extensions.Extensions );
            Assert.AreEqual( "test", assertionResponse.Extensions.Example );
            Assert.AreEqual( (ulong)4, assertionResponse.Extensions.UserVerificationMethod[0][0] );
            Assert.IsTrue( assertionResponse.Extensions.PRF.Enabled );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.Extensions.PRF.Results.First );
            CollectionAssert.AreEqual( new byte[] { 0xf1, 0xd0 }, assertionResponse.Extensions.PRF.Results.Second );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionTypeNotPublicKey()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 }
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.Invalid,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                }
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.AssertionResponseNotPublicKey, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionIdMissing()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.AssertionResponseIdMissing, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionRawIdMissing()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";

            var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.AssertionResponseRawIdMissing, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionUserHandleEmpty()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = Array.Empty<byte>(),
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.UserHandleIsEmpty, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionUserHandleNotOwnerOfPublicKey()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(false);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.UserHandleNotOwnerOfPublicKey, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionTypeNotWebAuthnGet()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.create",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.AssertionResponseTypeNotWebAuthnGet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionAppId()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";

            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Extensions = new AuthenticationExtensionsClientInputs() { AppID = "https://foo.bar" },
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 }
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = true,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.InvalidRpidHash, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionInvalidRpIdHash()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";

            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes("https://foo.bar")), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.InvalidRpidHash, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionUPRequirementNotMet()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";

            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                UserVerification = UserVerificationRequirement.Required,
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), 0, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                }
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.UserPresentFlagNotSet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionUVPolicyNotMet()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";

            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                UserVerification = UserVerificationRequirement.Required,
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                }
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.UserVerificationRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionBEPolicyRequired()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionBEPolicyDisallow()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BE, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Disallowed,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.BackupEligibilityRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionBSPolicyRequired()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
                type: "webauthn.get",
                challenge: challenge,
                origin: rp
            );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Required,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.BackupStateRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionBSPolicyDisallow()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";
            var authenticatorResponse = new AuthenticatorResponse(
            type: "webauthn.get",
            challenge: challenge,
            origin: rp
        );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV | AuthenticatorFlags.BS, 0, null).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    },
                }
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Disallowed,
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.BackupStateRequirementNotMet, ex.Result.Message );
        }

        [TestMethod]
        public void TestAuthenticatorAssertionStoredPublicKeyMissing()
        {
            var challenge = new byte[128];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( challenge );
            }
            var rp = "https://www.passwordless.dev";

            var authenticatorResponse = new AuthenticatorResponse(
               type: "webauthn.get",
               challenge: challenge,
               origin: rp
           );

            byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

            var options = new AssertionOptions
            {
                Challenge = challenge,
                RpId = rp,
                AllowCredentials = new[]
            {
                new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
            }
            };

            var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
            {
                AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null, new Extensions(new byte[] { 0x42 })).ToByteArray(),
                Signature = new byte[] { 0xf1, 0xd0 },
                ClientDataJson = clientDataJson,
                UserHandle = new byte[] { 0xf1, 0xd0 },
            };

            var assertionResponse = new AuthenticatorAssertionRawResponse()
            {
                Response = assertion,
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 0xf1, 0xd0 },
                RawId = new byte[] { 0xf1, 0xd0 },
                Extensions = new AuthenticationExtensionsClientOutputs()
                {
                    AppID = false,
                    AuthenticatorSelection = true,
                    Extensions = new string[] { "foo", "bar" },
                    Example = "test",
                    UserVerificationMethod = new ulong[][]
                {
                    new ulong[]
                    {
                        4 // USER_VERIFY_PASSCODE_INTERNAL
                    }
                },
                }
            };

            var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = rp,
                ServerName = rp,
                Origins = new HashSet<string> { rp },
            });

            IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken ) =>
        {
            return Task.FromResult(true);
        };

            var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, null, null, 0, callback));
            Assert.AreEqual( Fido2ErrorMessages.MissingStoredPublicKey, ex.Result.Message );
        }

        //[TestMethod]
        //public void TestAuthenticatorAssertionInvalidSignature()
        //{
        //    var challenge = new byte[128];
        //    using ( var rng = RandomNumberGenerator.Create() )
        //    {
        //        rng.GetBytes( challenge );
        //    }
        //    var rp = "https://www.passwordless.dev";

        //    var authenticatorResponse = new AuthenticatorResponse(
        //       type: "webauthn.get",
        //       challenge: challenge,
        //       origin: rp
        //   );

        //    byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        //    var options = new AssertionOptions
        //    {
        //        Challenge = challenge,
        //        RpId = rp,
        //        AllowCredentials = new[]
        //    {
        //        new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
        //    }
        //    };

        //    var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse()
        //    {
        //        AuthenticatorData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, null, new Extensions(new byte[] { 0x42 })).ToByteArray(),
        //        Signature = new byte[] { 0xf1, 0xd0 },
        //        ClientDataJson = clientDataJson,
        //        UserHandle = new byte[] { 0xf1, 0xd0 },
        //    };

        //    var assertionResponse = new AuthenticatorAssertionRawResponse()
        //    {
        //        Response = assertion,
        //        Type = PublicKeyCredentialType.PublicKey,
        //        Id = new byte[] { 0xf1, 0xd0 },
        //        RawId = new byte[] { 0xf1, 0xd0 },
        //        Extensions = new AuthenticationExtensionsClientOutputs()
        //        {
        //            AppID = false,
        //            AuthenticatorSelection = true,
        //            Extensions = new string[] { "foo", "bar" },
        //            Example = "test",
        //            UserVerificationMethod = new ulong[][]
        //        {
        //            new ulong[]
        //            {
        //                4 // USER_VERIFY_PASSCODE_INTERNAL
        //            }
        //        }
        //        }
        //    };

        //    var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
        //    {
        //        ServerDomain = rp,
        //        ServerName = rp,
        //        Origins = new HashSet<string> { rp }
        //    });

        //    IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken) =>
        //    {
        //        return Task.FromResult(true);
        //    };

        //    fido2_net_lib.Test.Fido2Tests.MakeEdDSA( out _, out var publicKey, out var privateKey );
        //    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, fido2_net_lib.Test.Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey).GetBytes(), null, 0, callback));
        //    Assert.AreEqual( Fido2ErrorMessages.InvalidSignature, ex.Result.Message );
        //}

        //[TestMethod]
        //public void TestAuthenticatorAssertionSignCountSignature()
        //{
        //    var challenge = new byte[128];
        //    using ( var rng = RandomNumberGenerator.Create() )
        //    {
        //        rng.GetBytes( challenge );
        //    }
        //    var rp = "https://www.passwordless.dev";

        //    var authenticatorResponse = new AuthenticatorResponse(
        //           type: "webauthn.get",
        //           challenge: challenge,
        //           origin: rp
        //       );

        //    byte[] clientDataJson = SerializationHelper.SerializeObjectToUtf8Bytes(authenticatorResponse, FidoSerializerContext.Default.AuthenticatorResponse);

        //    var options = new AssertionOptions
        //    {
        //        Challenge = challenge,
        //        RpId = rp,
        //        AllowCredentials = new[]
        //    {
        //        new PublicKeyCredentialDescriptor(new byte[] { 0xf1, 0xd0 })
        //    }
        //    };

        //    var authData = new AuthenticatorData(CryptoUtils.HashData256(Encoding.UTF8.GetBytes(rp)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 1, null, new Extensions(new byte[] { 0x42 })).ToByteArray();

        //    fido2_net_lib.Test.Fido2Tests.MakeEdDSA( out _, out var publicKey, out var expandedPrivateKey );
        //    Key privateKey = Key.Import(SignatureAlgorithm.Ed25519, expandedPrivateKey, KeyBlobFormat.RawPrivateKey);
        //    var cpk = fido2_net_lib.Test.Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.OKP, COSE.Algorithm.EdDSA, COSE.EllipticCurve.Ed25519, publicKey);

        //    var assertion = new AuthenticatorAssertionRawResponse.AssertionResponse
        //    {
        //        AuthenticatorData = authData,
        //        Signature = SignatureAlgorithm.Ed25519.Sign(privateKey, DataHelper.Concat(authData, CryptoUtils.HashData256(clientDataJson))),
        //        ClientDataJson = clientDataJson,
        //        UserHandle = new byte[] { 0xf1, 0xd0 },
        //    };

        //    var assertionResponse = new AuthenticatorAssertionRawResponse
        //    {
        //        Response = assertion,
        //        Type = PublicKeyCredentialType.PublicKey,
        //        Id = new byte[] { 0xf1, 0xd0 },
        //        RawId = new byte[] { 0xf1, 0xd0 },
        //        Extensions = new AuthenticationExtensionsClientOutputs()
        //        {
        //            AppID = false,
        //            AuthenticatorSelection = true,
        //            Extensions = new string[] { "foo", "bar" },
        //            Example = "test",
        //            UserVerificationMethod = new ulong[][]
        //        {
        //            new ulong[]
        //            {
        //                4 // USER_VERIFY_PASSCODE_INTERNAL
        //            }
        //        },
        //        }
        //    };

        //    var lib = new Fido2NetLib.Fido2(new Fido2NetLib.Fido2Configuration
        //    {
        //        ServerDomain = rp,
        //        ServerName = rp,
        //        Origins = new HashSet<string> { rp },
        //    });

        //    IsUserHandleOwnerOfCredentialIdAsync callback = (args, cancellationToken) =>
        //    {
        //        return Task.FromResult(true);
        //    };

        //    var ex = Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => lib.MakeAssertionAsync(assertionResponse, options, cpk.GetBytes(), null, 2, callback));
        //    Assert.AreEqual( Fido2ErrorMessages.SignCountIsLessThanSignatureCounter, ex.Result.Message );
        //}
    }
}