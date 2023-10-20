using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Test.Converters
{
    [TestClass]
    public class FidoEnumConverterTests
    {
        [TestMethod]
        public void CorrectlyUsesEnumMemberValue()
        {
            Assert.AreEqual( "\"secure_element\"", JsonConvert.SerializeObject( KeyProtection.SECURE_ELEMENT ) );
            Assert.AreEqual( KeyProtection.SECURE_ELEMENT, JsonConvert.DeserializeObject<KeyProtection>( "\"secure_element\"" ) );

            Assert.AreEqual( "\"public-key\"", JsonConvert.SerializeObject( PublicKeyCredentialType.PublicKey ) );
            Assert.AreEqual( PublicKeyCredentialType.PublicKey, JsonConvert.DeserializeObject<PublicKeyCredentialType>( "\"public-key\"" ) );
        }

        [TestMethod]
        public void CorrectlyFallsBackToMemberName()
        {
            Assert.AreEqual( "\"A\"", JsonConvert.SerializeObject( ABC.A ) );
            Assert.AreEqual( ABC.A, JsonConvert.DeserializeObject<ABC>( "\"A\"" ) );

            // Case insensitive
            Assert.AreEqual( "\"A\"", JsonConvert.SerializeObject( ABC.A ) );
            Assert.AreEqual( ABC.A, JsonConvert.DeserializeObject<ABC>( "\"a\"" ) );
        }

        [TestMethod]
        public void DeserializationIsCaseInsensitive()
        {
            Assert.AreEqual( "\"A\"", JsonConvert.SerializeObject( ABC.A ) );
            Assert.AreEqual( ABC.A, JsonConvert.DeserializeObject<ABC>( "\"a\"" ) );
        }

        [JsonConverter( typeof( FidoEnumConverter<ABC> ) )]
        public enum ABC
        {
            A = 1,
            B = 2,
            C = 3
        }
    }
}