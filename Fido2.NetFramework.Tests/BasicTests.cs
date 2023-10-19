using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido2.NetFramework.Tests
{
    [TestClass]
    public class BasicTests
    {
        [TestMethod]
        public void Options()
        {
            // arrange
            var _fido2Config = new Fido2Configuration()
            {
                ServerDomain            = "localhost",
                ServerName              = "FIDO2 Test",
                Origins                 = new HashSet<string>( new [] { "http://localhost" } ),
                TimestampDriftTolerance = 300000
            };

            var _fido2 = new Fido2NetLib.Fido2(_fido2Config);

            var authenticatorSelection = new AuthenticatorSelection
            {
                RequireResidentKey      = true,
                UserVerification        =  Fido2NetLib.Objects.UserVerificationRequirement.Preferred,
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform
            };

            var exts = new AuthenticationExtensionsClientInputs() { };

            // act
            var options =
                    _fido2.RequestNewCredential(
                        new Fido2User()
                        {
                            Id = Guid.NewGuid().ToByteArray(),
                            DisplayName = "Jan Kowalski",
                            Name = "Jan Kowalski"
                        },
                        new List<PublicKeyCredentialDescriptor>(),
                        authenticatorSelection,
                        AttestationConveyancePreference.None,
                        exts);

            // assert

            Assert.IsNotNull( options );
        }
    }
}
