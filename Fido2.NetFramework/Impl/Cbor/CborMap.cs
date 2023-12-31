﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Cbor
{
    public sealed class CborMap : CborObject, IReadOnlyDictionary<CborObject, CborObject>
    {
        private readonly List<KeyValuePair<CborObject, CborObject>> _items;

        public CborMap()
        {
            _items = new List<KeyValuePair<CborObject, CborObject>>();
        }

        public CborMap( int capacity )
        {
            _items = new List<KeyValuePair<CborObject, CborObject>>( capacity );
        }

        public override CborType Type => CborType.Map;

        public int Count => _items.Count;

        public IEnumerable<CborObject> Keys
        {
            get
            {
                foreach ( var item in _items )
                {
                    yield return item.Key;
                }
            }
        }

        public IEnumerable<CborObject> Values
        {
            get
            {
                foreach ( var item in _items )
                {
                    yield return item.Value;
                }
            }
        }

        public void Add( string key, CborObject value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), value ) );
        }

        public void Add( string key, bool value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), (CborBoolean)value ) );
        }

        public void Add( long key, CborObject value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( key ), value ) );
        }

        public void Add( long key, byte[] value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( key ), new CborByteString( value ) ) );
        }

        public void Add( long key, string value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( key ), new CborTextString( value ) ) );
        }

        public void Add( long key, long value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( key ), new CborInteger( value ) ) );
        }

        public void Add( string key, int value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), new CborInteger( value ) ) );
        }

        public void Add( string key, string value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), new CborTextString( value ) ) );
        }

        public void Add( string key, byte[] value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), new CborByteString( value ) ) );
        }

        public void Add( CborObject key, CborObject value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( key, value ) );
        }

        public void Add( string key, COSE.Algorithm value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), new CborInteger( (int)value ) ) );
        }

        public void Add( COSE.KeyCommonParameter key, COSE.KeyType value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( (int)key ), new CborInteger( (int)value ) ) );
        }

        public void Add( COSE.KeyCommonParameter key, COSE.Algorithm value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( (int)key ), new CborInteger( (int)value ) ) );
        }

        public void Add( COSE.KeyTypeParameter key, COSE.EllipticCurve value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( (int)key ), new CborInteger( (int)value ) ) );
        }

        public void Add( COSE.KeyTypeParameter key, byte[] value )
        {
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborInteger( (int)key ), new CborByteString( value ) ) );
        }

        public bool ContainsKey( CborObject key )
        {
            foreach ( var k in _items.Select( kvp => kvp.Key ) )
            {
                if ( k.Equals( key ) )
                    return true;
            }

            return false;
        }

        public bool TryGetValue( CborObject key, out CborObject value )
        {
            value = this[key];

            return value != null;
        }

        public IEnumerator<KeyValuePair<CborObject, CborObject>> GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        public CborObject this[COSE.KeyCommonParameter key] => GetValue( (long)key );

        public CborObject this[COSE.EllipticCurve key] => GetValue( (long)key );

        public CborObject this[COSE.KeyType key] => GetValue( (long)key );

        public CborObject this[COSE.KeyTypeParameter key] => GetValue( (long)key );

        public CborObject GetValue( long key )
        {
            foreach ( var item in _items )
            {
                if ( item.Key is CborInteger integerKey && integerKey.Value == key )
                {
                    return item.Value;
                }
            }

            throw new KeyNotFoundException( $"Key '{key}' not found" );
        }


        public CborObject this[CborObject key]
        {
            get
            {
                foreach ( var item in _items )
                {
                    if ( item.Key.Equals( key ) )
                    {
                        return item.Value;
                    }
                }

                return null;
            }
        }

        public override CborObject this[string name]
        {
            get
            {
                foreach ( var item in _items )
                {
                    if ( item.Key is CborTextString keyText && keyText.Value.Equals( name, StringComparison.Ordinal ) )
                    {
                        return item.Value;
                    }
                }

                return null;
            }
        }

        public void Remove( string key )
        {
            for ( int i = 0; i < _items.Count; i++ )
            {
                if ( _items[i].Key is CborTextString textKey && textKey.Value.Equals( key, StringComparison.Ordinal ) )
                {
                    _items.RemoveAt( i );

                    return;
                }
            }
        }

        public void Set( string key, CborObject value )
        {
            for ( int i = 0; i < _items.Count; i++ )
            {
                if ( _items[i].Key is CborTextString textKey && textKey.Value.Equals( key, StringComparison.Ordinal ) )
                {
                    _items[i] = new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), value );

                    return;
                }
            }
             
            _items.Add( new KeyValuePair<CborObject, CborObject>( new CborTextString( key ), value ) );
        }
    }
}