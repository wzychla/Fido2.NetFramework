using System;
using System.Text.Json;
using Newtonsoft.Json;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Serialization
{

    public sealed class AttestationTypeConverter : JsonConverter<AttestationType>
    {
        public override AttestationType ReadJson( JsonReader reader, Type objectType, AttestationType existingValue, bool hasExistingValue, Newtonsoft.Json.JsonSerializer serializer )
        {
            return AttestationType.Get( reader.Value as string );
        }

        public override void WriteJson( JsonWriter writer, AttestationType value, Newtonsoft.Json.JsonSerializer serializer )
        {
            writer.WriteValue( value.Value );
        }
    }
}