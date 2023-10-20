using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using Fido2NetLib.Exceptions;

namespace Fido2NetLib.Objects
{

    public sealed class AttestedCredentialData
    {
        /// <summary>
        /// Minimum length of the attested credential data structure.  AAGUID + credentialID length + credential ID + credential public key.
        /// <see cref="https://www.w3.org/TR/webauthn/#attested-credential-data"/>
        /// </summary>
        private const int _minLength = 20; // Marshal.SizeOf(typeof(Guid)) + sizeof(ushort) + sizeof(byte) + sizeof(byte)

        private const int _maxCredentialIdLength = 1_023;

        /// <summary>
        /// Instantiates an AttestedCredentialData object from an aaguid, credentialId, and credentialPublicKey
        /// </summary>
        /// <param name="aaGuid"></param>
        /// <param name="credentialId"></param>
        /// <param name="credentialPublicKey"></param>
        public AttestedCredentialData( Guid aaGuid, byte[] credentialId, CredentialPublicKey credentialPublicKey )
        {
            if ( credentialId == null ) throw new ArgumentNullException();
            if ( credentialPublicKey == null ) throw new ArgumentNullException();

            AaGuid = aaGuid;
            CredentialId = credentialId;
            CredentialPublicKey = credentialPublicKey;
        }

        /// <summary>
        /// The AAGUID of the authenticator. Can be used to identify the make and model of the authenticator.
        /// <see cref="https://www.w3.org/TR/webauthn/#aaguid"/>
        /// </summary>
        public Guid AaGuid { get; }

        /// <summary>
        /// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
        /// <see cref="https://www.w3.org/TR/webauthn/#credential-id"/>
        /// </summary>
        public byte[] CredentialId { get; }

        /// <summary>
        /// The credential public key encoded in COSE_Key format, as defined in 
        /// Section 7 of RFC8152, using the CTAP2 canonical CBOR encoding form.
        /// <see cref="https://www.w3.org/TR/webauthn/#credential-public-key"/>
        /// </summary>
        public CredentialPublicKey CredentialPublicKey { get; }

        public override string ToString()
        {
            return $"AttestedCredentialData(AAGUID:{AaGuid}, CredentialId: {CredentialId.ToHexString()}, CredentialPublicKey: {CredentialPublicKey})";
        }

        public byte[] ToByteArray()
        {
            List<byte> writer = new List<byte>();

            WriteTo( writer );

            return writer.ToArray();
        }

        public void WriteTo( List<byte> writer )
        {
            writer.AddRange( AaGuid.ToByteArray() );

            // Write the length of credential ID, as big endian bytes of a 16-bit unsigned integer
            writer.AddRange( BitConverter.GetBytes( (ushort)CredentialId.Length ).Reverse() );

            // Write CredentialId bytes
            writer.AddRange( CredentialId );

            // Write credential public key bytes
            writer.AddRange( CredentialPublicKey.GetBytes() );
        }

        public void WriteTo( IBufferWriter<byte> writer )
        {
            writer.WriteGuidBigEndian( AaGuid );

            // Write the length of credential ID, as big endian bytes of a 16-bit unsigned integer
            writer.WriteUInt16BigEndian( (ushort)CredentialId.Length );

            // Write CredentialId bytes
            writer.Write( CredentialId );

            // Write credential public key bytes
            writer.Write( CredentialPublicKey.GetBytes() );
        }

        /// <summary>
        /// Decodes attested credential data
        /// </summary>
        public static AttestedCredentialData Parse( byte[] data )
        {
            return Parse( data, out _ );
        }

        internal static AttestedCredentialData Parse( ReadOnlyMemory<byte> data, out int bytesRead )
        {
            if ( data.Length < _minLength )
                throw new Fido2VerificationException( Fido2ErrorCode.InvalidAttestedCredentialData, Fido2ErrorMessages.InvalidAttestedCredentialData_TooShort );

            int position = 0;

            // First 16 bytes is AAGUID
            var aaGuidBytes = data.ToArray().Take(16);

            position += 16;

            Guid aaGuid = GuidHelper.FromBigEndian(aaGuidBytes.ToArray());

            // Byte length of Credential ID, 16-bit unsigned big-endian integer. 
            var credentialIDLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position, 2).Span);
            if ( credentialIDLen > _maxCredentialIdLength )
                throw new Fido2VerificationException( Fido2ErrorCode.InvalidAttestedCredentialData, Fido2ErrorMessages.InvalidAttestedCredentialData_CredentialIdTooLong );

            position += 2;

            // Read the credential ID bytes
            var credentialID = data.Slice(position, credentialIDLen).ToArray();

            position += credentialIDLen;

            // "Determining attested credential data's length, which is variable, involves determining 
            // credentialPublicKey's beginning location given the preceding credentialId's length, and 
            // then determining the credentialPublicKey's length"


            // Read the CBOR object from the stream
            var credentialPublicKey = CredentialPublicKey.Decode(data.ToArray().Skip(position).ToArray(), out int read);

            position += read;

            bytesRead = position;

            return new AttestedCredentialData( aaGuid, credentialID, credentialPublicKey );
        }
    }
}