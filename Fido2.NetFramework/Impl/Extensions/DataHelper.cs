using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace Fido2NetLib
{

    public static class DataHelper
    {
        // https://stackoverflow.com/questions/1500194/c-looping-through-lines-of-multiline-string
        public static IEnumerable<string> EnumerateLines( this string s )
        {
            if ( string.IsNullOrWhiteSpace( s ) ) yield break;

            using ( var reader = new StringReader( s ) )
            {
                for ( string line = reader.ReadLine(); line != null; line = reader.ReadLine() )
                {
                    yield return line;
                }
            }
        }

        public static byte[] Concat( ReadOnlySpan<byte> a, ReadOnlySpan<byte> b )
        {
            var result = new byte[a.Length + b.Length];

            a.CopyTo( result );
            b.CopyTo( result.AsSpan( a.Length ) );

            return result;
        }

        public static byte[] Concat( ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c )
        {
            var result = new byte[a.Length + b.Length + c.Length];

            a.CopyTo( result );
            b.CopyTo( result.AsSpan( a.Length ) );
            c.CopyTo( result.AsSpan( a.Length + b.Length ) );

            return result;
        }

        public static byte[] Concat( ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e )
        {
            var result = new byte[a.Length + b.Length + c.Length + d.Length + e.Length];

            var position = 0;
            a.CopyTo( result );
            position += a.Length;

            b.CopyTo( result.AsSpan( position ) );
            position += b.Length;

            c.CopyTo( result.AsSpan( position ) );
            position += c.Length;

            d.CopyTo( result.AsSpan( position ) );
            position += d.Length;

            e.CopyTo( result.AsSpan( position ) );

            return result;
        }

        // https://stackoverflow.com/questions/16999604/convert-string-to-hex-string-in-c-sharp
        public static string ToHexString( this byte[] bytes )
        {
            var sb = new StringBuilder();

            foreach ( var t in bytes )
            {
                sb.Append( t.ToString( "X2" ) );
            }

            return sb.ToString(); // returns: "48656C6C6F20776F726C64" for "Hello world"
        }

        public static byte[] FromHexString( this string hexString )
        {
            var bytes = new byte[hexString.Length / 2];
            for ( var i = 0; i < bytes.Length; i++ )
            {
                bytes[i] = Convert.ToByte( hexString.Substring( i * 2, 2 ), 16 );
            }

            return bytes; // returns: "Hello world" for "48656C6C6F20776F726C64"
        }
    }
}