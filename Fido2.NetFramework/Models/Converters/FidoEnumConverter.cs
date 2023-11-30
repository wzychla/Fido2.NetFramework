using System;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Fido2NetLib
{

    public sealed class FidoEnumConverter<T> : JsonConverter<T>
        where T : struct, Enum
    {
        public override T ReadJson( JsonReader reader, Type objectType, T existingValue, bool hasExistingValue, JsonSerializer serializer )
        {
            string text = reader.Value as string;

            if ( string.IsNullOrWhiteSpace( text ) )
            {
                return (T)Enum.ToObject( typeof(T), 0 );
            }

            if ( EnumNameMapper<T>.TryGetValue( text, out T value ) )
            {
                return value;
            }
            else
            {
                throw new JsonException( $"Invalid enum value = {text}" );
            }
        }

        public override void WriteJson( JsonWriter writer, T value, JsonSerializer serializer )
        {
            writer.WriteValue( EnumNameMapper<T>.GetName( value ) );
        }
    }
}