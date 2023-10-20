using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Fido2NetLib;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Test
{
    [TestClass]
    public class Asn1Tests
    {
        [TestMethod]
        public void EncodeTpmSan()
        {
            Assert.AreEqual( "MG2kazBpMRYwFAYFZ4EFAgEMC2lkOkZGRkZGMUQwMTcwNQYFZ4EFAgIMLEZJRE8yLU5FVC1MSUItVGVzdFRQTUFpa0NlcnRTQU5UQ0dDb25mb3JtYW50MRYwFAYFZ4EFAgMMC2lkOkYxRDAwMDAy", Convert.ToBase64String( TpmSanEncoder.Encode(
                (new Oid( "2.23.133.2.1" ), "id:FFFFF1D0"),
                (new Oid( "2.23.133.2.2" ), "FIDO2-NET-LIB-TestTPMAikCertSANTCGConformant"),
                (new Oid( "2.23.133.2.3" ), "id:F1D00002")
            ) ) );
        }

        [TestMethod]
        public void DecodeObjectIdentifierAsOctetString()
        {
            byte[] data = Convert.FromBase64String("MD8wPaA7oDmGN2h0dHBzOi8vbWRzMy5jZXJ0aW5mcmEuZmlkb2FsbGlhbmNlLm9yZy9jcmwvTURTQ0EtMS5jcmw=");

            var decoded = Asn1Element.Decode(data);

            Assert.AreEqual( new Asn1Tag( TagClass.ContextSpecific, (int)UniversalTagNumber.ObjectIdentifier ), decoded[0][0][0][0].Tag );

            var cdp = Encoding.ASCII.GetString(decoded[0][0][0][0].GetOctetString(decoded[0][0][0][0].Tag));

            Assert.AreEqual( "https://mds3.certinfra.fidoalliance.org/crl/MDSCA-1.crl", cdp );
        }

        [TestMethod]
        public void DecodeEcDsaSig()
        {
            byte[] ecDsaSig = Convert.FromBase64String("MEUCIDelsTyfT/3Z6UO1KBz1j/GBoQmDN/2MXxsfGZNon1dsAiEAqsl2tTaUhnNoFTokqm4B/RegC9y5z/bSsAwtBXsQwdg=");

            var decoded = Asn1Element.Decode(ecDsaSig);

            Assert.AreEqual( Asn1Tag.Integer, decoded[0].Tag );
            Assert.AreEqual( Asn1Tag.Integer, decoded[1].Tag );

            var r = decoded[0].GetIntegerBytes();
            var s = decoded[1].GetIntegerBytes();

            Assert.AreEqual( "N6WxPJ9P/dnpQ7UoHPWP8YGhCYM3/YxfGx8Zk2ifV2w=", Convert.ToBase64String( r.ToArray() ) );
            Assert.AreEqual( "AKrJdrU2lIZzaBU6JKpuAf0XoAvcuc/20rAMLQV7EMHY", Convert.ToBase64String( s.ToArray() ) );


        }
        [TestMethod]
        public void DecodeBitString()
        {
            byte[] data = Convert.FromBase64String("AwIFIA==");

            var element = Asn1Element.Decode(data);

            Assert.AreEqual( Asn1Tag.PrimitiveBitString, element.Tag );

            Assert.AreEqual( "IA==", Convert.ToBase64String( element.GetBitString() ) );
        }

        [TestMethod]
        public void DecodeConstructedObject()
        {
            byte[] data = Convert.FromBase64String("MCShIgQgnGACFUCz4Zg03+N+xiRFyJ4bKU95LORrlBPDIw7zhoE=");

            var element = Asn1Element.Decode(data);

            Assert.IsTrue( element.IsConstructed );

            element[0][0].CheckTag( Asn1Tag.PrimitiveOctetString );

            Assert.AreEqual( "nGACFUCz4Zg03+N+xiRFyJ4bKU95LORrlBPDIw7zhoE=", Convert.ToBase64String( element[0][0].GetOctetString() ) );
        }

        [TestMethod]
        public void DecodeOctetString()
        {
            byte[] data = Convert.FromBase64String("MIHPAgECCgEAAgEBCgEABCDc0UoXtU1CwwItW3ne2faKDcFCabFI31BufXEFVK/ENwQAMGm/hT0IAgYBXtPjz6C/hUVZBFcwVTEvMC0EKGNvbS5hbmRyb2lkLmtleXN0b3JlLmFuZHJvaWRrZXlzdG9yZWRlbW8CAQExIgQgdM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2JgwMqEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DeAMCAQK/hT4DAgEAv4U/AgUA");

            var element = Asn1Element.Decode(data);

            Assert.IsTrue( element[4].IsOctetString );
            Assert.AreEqual( Asn1Tag.PrimitiveOctetString, element[4].Tag );


            Assert.AreEqual( "3NFKF7VNQsMCLVt53tn2ig3BQmmxSN9Qbn1xBVSvxDc=", Convert.ToBase64String( element[4].GetOctetString() ) );
        }

        [TestMethod]
        public void Decode()
        {
            byte[] data = Convert.FromBase64String("MIHPAgECCgEAAgEBCgEABCDc0UoXtU1CwwItW3ne2faKDcFCabFI31BufXEFVK/ENwQAMGm/hT0IAgYBXtPjz6C/hUVZBFcwVTEvMC0EKGNvbS5hbmRyb2lkLmtleXN0b3JlLmFuZHJvaWRrZXlzdG9yZWRlbW8CAQExIgQgdM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2JgwMqEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb+DeAMCAQK/hT4DAgEAv4U/AgUA");

            var element = Asn1Element.Decode(data);

            Assert.AreEqual( Asn1Tag.Sequence, element.Tag );
            Assert.AreEqual( 8, element.Sequence.Count );
            CollectionAssert.AreEqual( new[] { 2, 10, 2, 10, 4, 4, 16, 16 }, element.Sequence.Select( e => e.TagValue ).ToArray() );

            Assert.AreEqual( Asn1Tag.Integer, element[0].Tag );
            Assert.AreEqual( Asn1Tag.Enumerated, element[1].Tag );
            Assert.AreEqual( Asn1Tag.Integer, element[2].Tag );
            Assert.AreEqual( Asn1Tag.Enumerated, element[3].Tag );
            Assert.AreEqual( Asn1Tag.PrimitiveOctetString, element[4].Tag );
            Assert.AreEqual( Asn1Tag.PrimitiveOctetString, element[5].Tag );
            Assert.AreEqual( Asn1Tag.Sequence, element[6].Tag );
            Assert.AreEqual( Asn1Tag.Sequence, element[7].Tag );

            Assert.IsTrue( element[0].IsInteger );
            Assert.AreEqual( 2, element[0].GetInt32() );

            Assert.IsTrue( element[4].IsOctetString );

            Assert.IsTrue( element[6].IsSequence );

            CollectionAssert.AreEqual( new[] { 701, 709 }, element[6].Sequence.Select( e => e.TagValue ).ToArray() );
        }

        [TestMethod]
        public void DecodeContextSpecificConstructedSet()
        {
            byte[] data = Convert.FromBase64String("MGACAQMgAwQBAAIBAiADBAEABCABfDdfwPehWBVL2KIcBZflxAraVzzPoB2bIb9ZUqt97gQQ7PlbfpnmqCgDZgrEb1eHiTARv4U9BgIEYWcoF6EFMQMCAQEwB7+FPgMCAQA=");

            var element = Asn1Element.Decode(data);

            Assert.AreEqual( Asn1Tag.Sequence, element.Tag );
            Assert.AreEqual( 8, element.Sequence.Count );
            CollectionAssert.AreEqual( new[] { 2, 0, 2, 0, 4, 4, 16, 16 }, element.Sequence.Select( e => e.TagValue ).ToArray() );

            var element6 = element[6];
            var element6_1 = element[6][1];
            var element6_1_0 = element[6][1][0];
            var element6_1_0_0 = element[6][1][0][0];

            Assert.IsTrue( element6.IsSequence );
            Assert.AreEqual( 701, element6[0].TagValue );


            Assert.IsTrue( element6_1.IsConstructed );
            Assert.AreEqual( TagClass.ContextSpecific, element6_1.TagClass );
            Assert.AreEqual( 1, element6_1.TagValue );
            Assert.IsTrue( element6_1.Sequence.Count() == 1);

            Assert.AreEqual( Asn1Tag.SetOf, element6_1_0.Tag );

            Assert.AreEqual( 2, element6_1_0_0.TagValue );
            Assert.AreEqual( 1, element6_1_0_0.GetInt32() );
        }
    }
}