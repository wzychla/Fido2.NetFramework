using System;
using System.IO;

namespace fido2_net_lib
{

    internal static class CertInfoHelper
    {
        public static byte[] CreateCertInfo(
            ReadOnlySpan<byte> magic,
            ReadOnlySpan<byte> type,
            ReadOnlySpan<byte> qualifiedSigner,
            ReadOnlySpan<byte> extraData,
            ReadOnlySpan<byte> clock,
            ReadOnlySpan<byte> resetCount,
            ReadOnlySpan<byte> restartCount,
            ReadOnlySpan<byte> safe,
            ReadOnlySpan<byte> firmwareRevision,
            ReadOnlySpan<byte> tPM2BName,
            ReadOnlySpan<byte> attestedQualifiedNameBuffer )
        {
            using ( var stream = new MemoryStream() )
            {

                stream.Write( magic.ToArray(), 0, magic.Length );
                stream.Write( type.ToArray(), 0, type.Length );
                stream.Write( qualifiedSigner.ToArray(), 0, qualifiedSigner.Length );
                stream.Write( extraData.ToArray(), 0, extraData.Length );
                stream.Write( clock.ToArray(), 0, clock.Length );
                stream.Write( resetCount.ToArray(), 0, resetCount.Length );
                stream.Write( restartCount.ToArray(), 0, restartCount.Length );
                stream.Write( safe.ToArray(), 0, safe.Length );
                stream.Write( firmwareRevision.ToArray(), 0, firmwareRevision.Length );
                stream.Write( tPM2BName.ToArray(), 0, tPM2BName.Length );
                stream.Write( attestedQualifiedNameBuffer.ToArray(), 0, attestedQualifiedNameBuffer.Length );

                return stream.ToArray();
            }
        }
    }
}