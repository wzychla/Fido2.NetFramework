using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using Fido2NetLib;

using Test;

namespace fido2_net_lib
{

    internal static class PubAreaHelper
    {
        internal static byte[] CreatePubArea(
            TpmAlg type,
            ReadOnlySpan<byte> alg,
            ReadOnlySpan<byte> attributes,
            ReadOnlySpan<byte> policy,
            ReadOnlySpan<byte> symmetric,
            ReadOnlySpan<byte> scheme,
            ReadOnlySpan<byte> keyBits,
            ReadOnlySpan<byte> exponent,
            ReadOnlySpan<byte> curveID,
            ReadOnlySpan<byte> kdf,
            ReadOnlySpan<byte> unique = default )
        {
            using ( var stream = new MemoryStream() )
            {
                if ( type is TpmAlg.TPM_ALG_ECC )
                {
                    stream.Write( type.ToUInt16BigEndianBytes().ToArray(), 0, type.ToUInt16BigEndianBytes().Length );
                    stream.Write( alg.ToArray(), 0, alg.Length );
                    stream.Write( attributes.ToArray(), 0, attributes.Length );
                    stream.Write( GetUInt16BigEndianBytes( policy.Length ).ToArray(), 0, GetUInt16BigEndianBytes( policy.Length ).Length ); 
                    stream.Write( policy.ToArray(), 0, policy.Length );
                    stream.Write( symmetric.ToArray(), 0, symmetric.Length );
                    stream.Write( scheme.ToArray(), 0, scheme.Length );
                    stream.Write( curveID.ToArray(), 0, curveID.Length );
                    stream.Write( kdf.ToArray(), 0, kdf.Length );
                    stream.Write( unique.ToArray(), 0, unique.Length );
                }
                else
                {
                    stream.Write( type.ToUInt16BigEndianBytes().ToArray(), 0, type.ToUInt16BigEndianBytes().Length );
                    stream.Write( alg.ToArray(), 0, alg.Length );
                    stream.Write( attributes.ToArray(), 0, attributes.Length );
                    stream.Write( GetUInt16BigEndianBytes( policy.Length ).ToArray(), 0, GetUInt16BigEndianBytes( policy.Length ).Length );
                    stream.Write( policy.ToArray(), 0, policy.Length );
                    stream.Write( symmetric.ToArray(), 0, symmetric.Length );
                    stream.Write( scheme.ToArray(), 0, scheme.Length );
                    stream.Write( keyBits.ToArray(), 0, keyBits.Length );
                    stream.Write( BitConverter.GetBytes( exponent[0] + ( exponent[1] << 8 ) + ( exponent[2] << 16 ) ), 0, BitConverter.GetBytes( exponent[0] + ( exponent[1] << 8 ) + ( exponent[2] << 16 ) ).Length );
                    stream.Write( GetUInt16BigEndianBytes( unique.Length ).ToArray(), 0, GetUInt16BigEndianBytes( unique.Length ).Length );
                    stream.Write( unique.ToArray(), 0, unique.Length );
                }

                return stream.ToArray();
            }
        }

        private static byte[] GetUInt16BigEndianBytes( int value )
        {
            return GetUInt16BigEndianBytes( (UInt16)value );
        }

        private static byte[] GetUInt16BigEndianBytes( UInt16 value )
        {
            var buffer = new byte[2];

            BinaryPrimitives.WriteUInt16BigEndian( buffer, value );

            return buffer;
        }
    }
}