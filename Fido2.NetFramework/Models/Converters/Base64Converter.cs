using System;
using Newtonsoft.Json;

namespace Fido2NetLib
{

    /// <summary>
    /// Custom Converter for encoding/encoding byte[] using Base64Url instead of default Base64.
    /// </summary>
    public sealed class Base64UrlConverter : JsonConverter<byte[]>
    {
        public override byte[] ReadJson( JsonReader reader, Type objectType, byte[] existingValue, bool hasExistingValue, JsonSerializer serializer )
        {
            if ( reader != null && reader.Value != null )
                return Base64Url.Decode( ( (string)reader.Value ).ToCharArray() );
            else
                return null;
        }

        public override void WriteJson( JsonWriter writer, byte[] value, JsonSerializer serializer )
        {
            writer.WriteValue( Base64Url.Encode( value ) );
        }
    }
}