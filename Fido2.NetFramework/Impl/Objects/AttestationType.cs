using System;
using Newtonsoft.Json;

using Fido2NetLib.Serialization;

namespace Fido2NetLib.Objects
{

    [JsonConverter( typeof( AttestationTypeConverter ) )]
    public sealed class AttestationType : IEquatable<AttestationType>
    {
        public static readonly AttestationType None = new AttestationType("none");
        public static readonly AttestationType Basic = new AttestationType("basic");
        public static readonly AttestationType Self = new AttestationType("self");
        public static readonly AttestationType AttCa = new AttestationType("attca");
        public static readonly AttestationType ECDAA = new AttestationType("ecdaa");

        private readonly string _value;

        internal AttestationType( string value )
        {
            _value = value;
        }

        public string Value => _value;

        public static implicit operator string( AttestationType op ) { return op.Value; }

        public static bool operator ==( AttestationType e1, AttestationType e2 )
        {
            if ( e1 is null )
                return e2 is null;

            return e1.Equals( e2 );
        }

        public static bool operator !=( AttestationType e1, AttestationType e2 )
        {
            return !( e1 == e2 );
        }

        public override bool Equals( object obj )
        {
            return obj is AttestationType other && Equals( other );
        }

        public bool Equals( AttestationType other )
        {
            if ( ReferenceEquals( this, other ) )
                return true;

            if ( other is null )
                return false;

            return string.Equals( Value, other.Value, StringComparison.Ordinal );
        }

        public override int GetHashCode() => Value.GetHashCode();

        public override string ToString() => Value;

        internal static AttestationType Get( string value )
        {
            switch (value)
            {
                case "none": return None;
                case "basic": return Basic;
                case "self": return Self;
                case "attca": return AttCa;
                case "ecdaa": return ECDAA;
                default: return new AttestationType( value );
            };
        }
    }
}