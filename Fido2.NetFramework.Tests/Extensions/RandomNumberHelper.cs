using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Fido2NetLib.Test
{
    public static class RandomNumberHelper
    {
        public static byte[] GetBytes( int numberOfBytes )
        {
            byte[] bytes = new byte[numberOfBytes];

            Fill( bytes );

            return bytes;
        }
        public static void Fill( byte[] bytes )
        {
            if ( bytes == null || bytes.Length == 0 ) return;

            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( bytes );
            }
        }
    }
}
