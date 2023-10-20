using System;
using System.Collections.Generic;
using System.Text;

using Fido2NetLib;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace fido2_net_lib.Test
{
    [TestClass]
    public class Base64UrlTest
    {
        [TestMethod]
        [DynamicData( nameof( GetData ) )]
        public void EncodeAndDecodeResultsAreEqual( byte[] data )
        {
            // Act
            var encodedString = Base64Url.Encode(data);
            var decodedBytes = Base64Url.Decode(encodedString.ToCharArray());

            // Assert
            CollectionAssert.AreEqual( data, decodedBytes );

            // Ensure this also works with the Utf8 decoder
            CollectionAssert.AreEqual( data, Base64Url.DecodeUtf8( Encoding.UTF8.GetBytes( encodedString ) ) );
        }

        public static IEnumerable<object[]> GetData
        {
            get 
            {
                return new[]
                {
                    new object[] { Encoding.UTF8.GetBytes( "A" ) },
                    new object[] { Encoding.UTF8.GetBytes( "This is a string fragment to test Base64Url encoding & decoding." ) },
                    new object[] { Array.Empty<byte>() },
                };
            }
        }


        [TestMethod]
        public static void Format_BadBase64Char()
        {
            const string Format_BadBase64Char = "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.";
            var ex = Assert.ThrowsException<FormatException>(() => Base64Url.Decode("rCQqQMqKVO/geUyc9aENh85Mt2g1JHAUKUG27WZVE68===".ToCharArray()));
            Assert.AreEqual( Format_BadBase64Char, ex.Message );

            ex = Assert.ThrowsException<FormatException>( () => Base64Url.DecodeUtf8( Encoding.UTF8.GetBytes( "rCQqQMqKVO/geUyc9aENh85Mt2g1JHAUKUG27WZVE68===" ) ) );
            Assert.AreEqual( Format_BadBase64Char, ex.Message );
        }
    }
}