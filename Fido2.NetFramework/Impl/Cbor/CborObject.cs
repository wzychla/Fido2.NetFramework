using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Fido2NetLib.Cbor
{

    public abstract class CborObject
    {
        public abstract CborType Type { get; }

        public static CborObject Decode( ReadOnlyMemory<byte> data )
        {
            var reader = new CborReader(data);

            return Read( reader );
        }

        public static CborObject Decode( ReadOnlyMemory<byte> data, out int bytesRead )
        {
            var reader = new CborReader(data);

            var result = Read(reader);

            bytesRead = data.Length - reader.BytesRemaining;

            return result;
        }

        public virtual CborObject this[int index] => null;

        public virtual CborObject this[string name] => null;

        public static explicit operator string( CborObject obj )
        {
            return ( (CborTextString)obj ).Value;
        }

        public static explicit operator byte[]( CborObject obj )
        {
            return ( (CborByteString)obj ).Value;
        }

        public static explicit operator int( CborObject obj )
        {
            return (int)( (CborInteger)obj ).Value;
        }

        public static explicit operator long( CborObject obj )
        {
            return ( (CborInteger)obj ).Value;
        }

        public static explicit operator bool( CborObject obj )
        {
            return ( (CborBoolean)obj ).Value;
        }

        private static CborObject Read( CborReader reader )
        {
            CborReaderState s = reader.PeekState();

            switch (s)
            {
                case CborReaderState.StartMap: return ReadMap( reader );
                case CborReaderState.StartArray: return ReadArray( reader );
                case CborReaderState.TextString: return new CborTextString( reader.ReadTextString() );
                case CborReaderState.Boolean: return (CborBoolean)reader.ReadBoolean();
                case CborReaderState.ByteString: return new CborByteString( reader.ReadByteString() );
                case CborReaderState.UnsignedInteger: return new CborInteger( reader.ReadInt64() );
                case CborReaderState.NegativeInteger: return new CborInteger( reader.ReadInt64() );
                case CborReaderState.Null: return ReadNull( reader );
                default: throw new Exception( $"Unhandled state. Was {s}" );
            };
        }

        private static CborNull ReadNull( CborReader reader )
        {
            reader.ReadNull();

            return CborNull.Instance;
        }

        private static CborArray ReadArray( CborReader reader )
        {
            int? count = reader.ReadStartArray();

            var items = count != null
            ? new List<CborObject>(count.Value)
            : new List<CborObject>();

            var readerPeekState = reader.PeekState();

            while ( !( readerPeekState is CborReaderState.EndArray || readerPeekState is CborReaderState.Finished ) )
            {
                items.Add( Read( reader ) );

                readerPeekState = reader.PeekState();
            }

            reader.ReadEndArray();

            return new CborArray( items );
        }

        private static CborMap ReadMap( CborReader reader )
        {
            int? count = reader.ReadStartMap();

            var map = count.HasValue ? new CborMap(count.Value) : new CborMap();

            var readerPeekState = reader.PeekState();

            while ( !( readerPeekState is CborReaderState.EndMap || readerPeekState is CborReaderState.Finished ) )
            {
                CborObject k = Read(reader);
                CborObject v = Read(reader);

                map.Add( k, v );

                readerPeekState = reader.PeekState();
            }

            reader.ReadEndMap();

            return map;
        }

        public byte[] Encode()
        {
            var writer = new CborWriter();

            writer.WriteObject( this );

            return writer.Encode();
        }
    }
}