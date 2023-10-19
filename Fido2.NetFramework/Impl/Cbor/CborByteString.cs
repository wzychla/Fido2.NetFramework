using System;

namespace Fido2NetLib.Cbor
{

    public sealed class CborByteString : CborObject
    {
        public CborByteString( byte[] value )
        {
            if ( value == null ) throw new ArgumentNullException();

            Value = value;
        }

        public override CborType Type => CborType.ByteString;

        public byte[] Value { get; }

        public int Length => Value.Length;

        public static implicit operator byte[]( CborByteString value ) => value.Value;
    }
}