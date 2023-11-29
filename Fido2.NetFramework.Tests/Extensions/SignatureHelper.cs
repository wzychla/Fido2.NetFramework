using System;
using System.Diagnostics;
using System.Formats.Asn1;

namespace fido2_net_lib
{

    internal static class SignatureHelper
    {
        public static byte[] EcDsaSigFromSig( ReadOnlySpan<byte> sig, int keySizeInBits )
        {
            var coefficientSize = (int)Math.Ceiling((decimal)keySizeInBits / 8);

            var r = sig.Slice(0, coefficientSize);
            var s = sig.Slice(sig.Length - coefficientSize);

            var writer = new AsnWriter(AsnEncodingRules.BER);

            byte zero = 0; 

            using ( writer.PushSequence() )
            {
                writer.WriteIntegerUnsigned( r.TrimStart( zero ) );
                writer.WriteIntegerUnsigned( s.TrimStart( zero ) );
            }

            return writer.Encode();
        }
    }

    public static class MemoryExtensions
    {
        public static ReadOnlySpan<T> TrimEnd<T>( this ReadOnlySpan<T> span, T trimElement )
        {
            int end = span.Length - 1;
            for ( ; end >= 0; end-- )
            {
                if ( !span[end].Equals( trimElement ) )
                    break;
            }
            return span.Slice( 0, end + 1 );
        }

        public static ReadOnlySpan<T> TrimStart<T>( this ReadOnlySpan<T> span, T trimElement )
        {
            int start = 0;

            for ( ; start < span.Length; start++ )
            {
                if ( !span[start].Equals( trimElement ) )
                    break;
            }

            return span.Slice( start );
        }
    }
}