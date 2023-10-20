//using fido2_net_lib.Test;

//using Fido2NetLib;
//using Fido2NetLib.Cbor;
//using Fido2NetLib.Exceptions;
//using Fido2NetLib.Objects;

//namespace Test.Attestation;

//public class None : Fido2Tests.Attestation
//{
//    public None()
//    {
//        _attestationObject = new CborMap { { "fmt", "none" } };
//    }

//    [TestMethod]
//    public async Task TestNone()
//    {
//        foreach (var (keyType, alg, crv) in Fido2Tests._validCOSEParameters)
//        {
//            // P256K is not supported on macOS
//            if (OperatingSystem.IsMacOS() && crv is COSE.EllipticCurve.P256K)
//                continue;

//            _attestationObject.Add("attStmt", new CborMap());
//            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey((keyType, alg, crv));
//            Fido2.CredentialMakeResult res;

//            res = await MakeAttestationResponseAsync();

//            Assert.AreEqual(string.Empty, res.ErrorMessage);
//            Assert.AreEqual("ok", res.Status);
//            Assert.AreEqual(_aaguid, res.Result.AaGuid);
//            Assert.AreEqual(_signCount, res.Result.SignCount);
//            Assert.AreEqual("none", res.Result.AttestationFormat);
//            Assert.AreEqual(_credentialID, res.Result.Id);
//            Assert.IsNull(res.Result.ErrorMessage);
//            Assert.AreEqual(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
//            Assert.IsNull(res.Result.Status);
//            Assert.AreEqual("Test User", res.Result.User.DisplayName);
//            Assert.AreEqual("testuser"u8.ToArray(), res.Result.User.Id);
//            Assert.AreEqual("testuser", res.Result.User.Name);
//            _attestationObject = new CborMap { { "fmt", "none" } };
//        }
//    }

//    [TestMethod]
//    public async Task TestNoneWithAttStmt()
//    {
//        _attestationObject.Add("attStmt", new CborMap { { "foo", "bar" } });
//        _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(Fido2Tests._validCOSEParameters[0]);

//        var ex = await Assert.ThrowsExceptionAsync<Fido2VerificationException>(() => MakeAttestationResponseAsync());

//        Assert.AreEqual(Fido2ErrorCode.InvalidAttestation, ex.Code);
//        Assert.AreEqual("Attestation format none should have no attestation statement", ex.Message);
//    }
//}
