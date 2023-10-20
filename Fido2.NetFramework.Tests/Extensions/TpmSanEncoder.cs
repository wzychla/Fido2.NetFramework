using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Test
{

    internal static class TpmSanEncoder
    {
        internal static class Oids
        {
            public static readonly Oid ManuTestMethodurer = new Oid("2.23.133.2.1");
            public static readonly Oid Model = new Oid("2.23.133.2.2");
            public static readonly Oid Version = new Oid("2.23.133.2.3");
        }

        public static byte[] Encode( string manuTestMethodurer, string model, string version )
        {
            return Encode(
                (Oids.ManuTestMethodurer, manuTestMethodurer),
                (Oids.Model, model),
                (Oids.Version, version)
            );
        }

        public static byte[] Encode( params (Oid, string)[] items )
        {
            var writer = new AsnWriter(AsnEncodingRules.BER);

            using ( writer.PushSequence() )
            using ( writer.PushSequence( new Asn1Tag( TagClass.ContextSpecific, 4, true ) ) )
            {
                using ( writer.PushSequence() )
                {
                    foreach ( (Oid oid, string value) in items )
                    {
                        WriteSet( writer, oid, value );
                    }
                }
            }

            return writer.Encode();
        }

        private static void WriteSet( AsnWriter writer, Oid oid, string text )
        {
            using ( writer.PushSetOf() )
            using ( writer.PushSequence() )
            {
                writer.WriteObjectIdentifier( oid.Value );
                writer.WriteCharacterString( UniversalTagNumber.UTF8String, text );
            }
        }
    }
}