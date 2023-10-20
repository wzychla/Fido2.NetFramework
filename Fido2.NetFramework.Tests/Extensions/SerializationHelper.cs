using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido2NetLib.Test
{
    public class SerializationHelper
    {
        public static byte[] SerializeObjectToUtf8Bytes(object o)
        {
            if ( o == null ) return Array.Empty<byte>();

            var serialized = JsonConvert.SerializeObject( o );
            var encoded = Encoding.UTF8.GetBytes( serialized );

            return encoded;
        }
        public static byte[] SerializeObjectToUtf8Bytes( object o, JsonSerializerSettings settings )
        {
            if ( o == null ) return Array.Empty<byte>();

            var serialized = JsonConvert.SerializeObject( o, settings );
            var encoded = Encoding.UTF8.GetBytes( serialized );

            return encoded;
        }
    }
}
