using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects.Tests
{
    [TestClass]
    public class AttestationTypeTests
    {
        [TestMethod]
        public void ImplicitlyConvertibleToString()
        {
            Assert.AreEqual( "none", AttestationType.None );
        }

        [TestMethod]
        public void CanSerialize()
        {
            Assert.AreEqual( "\"none\"", JsonConvert.SerializeObject( AttestationType.None ) );
            Assert.AreEqual( "\"ecdaa\"", JsonConvert.SerializeObject( AttestationType.ECDAA ) );
        }

        [TestMethod]
        public void CanDeserialize()
        {
            Assert.AreEqual( AttestationType.None, JsonConvert.DeserializeObject<AttestationType>( "\"none\"" ) );
            Assert.AreEqual( AttestationType.ECDAA, JsonConvert.DeserializeObject<AttestationType>( "\"ecdaa\"" ) );
        }
    }
}