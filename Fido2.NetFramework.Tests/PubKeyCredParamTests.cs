using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace fido2_net_lib.Test
{
    [TestClass]
    public class PubKeyCredParamTests
    {
        [TestMethod]
        public void CanDeserializeES256()
        {
            string json = "{\"type\":\"public-key\",\"alg\":-7}";

            var model = JsonConvert.DeserializeObject<PubKeyCredParam>(json);

            Assert.AreEqual( PublicKeyCredentialType.PublicKey, model.Type );
            Assert.AreEqual( COSE.Algorithm.ES256, model.Alg );
        }

        [TestMethod]
        public void CanDeserializeES256K()
        {
            string json = "{\"type\":\"public-key\",\"alg\":-47}";

            var model = JsonConvert.DeserializeObject<PubKeyCredParam>(json);

            Assert.AreEqual( PublicKeyCredentialType.PublicKey, model.Type );
            Assert.AreEqual( COSE.Algorithm.ES256K, model.Alg );
        }
    }
}