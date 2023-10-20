using Fido2NetLib.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Fido2NetLib.Test
{
    [TestClass]
    public class EnumExtensionTest
    {
        [TestMethod]
        public void TestToEnum()
        {
            foreach ( var enumName in Enum.GetNames( typeof( AttestationConveyancePreference ) ) )
            {
                enumName.ToEnum<AttestationConveyancePreference>();
            }
        }

        [TestMethod]
        // valid
        [DataRow( "INDIRECT", false )]
        [DataRow( "indIrEcT", false )]
        [DataRow( "indirect", false )]
        [DataRow( nameof( AttestationConveyancePreference.Indirect ), false )]
        // invalid
        [DataRow( "Indirect_Invalid", true )]
        public void TestToEnumWithIgnoringCase( string value, bool shouldThrow )
        {
            var exception = Record.Exception(() => value.ToEnum<AttestationConveyancePreference>());

            if ( shouldThrow )
            {
                Assert.IsInstanceOfType<ArgumentException>( exception );
            }
            else
            {
                Assert.IsNull( exception );
            }
        }

        [TestMethod]
        // valid
        [DataRow( "CROSS-PLATFORM", false )]
        [DataRow( "cRoss-PlatfoRm", false )]
        [DataRow( "cross-platform", false )]
        // invalid
        [DataRow( "cross_platform", true )]
        [DataRow( "cross-platforms", true )]
        [DataRow( "CROSS_PLATFORM", true )]
        public void TestToEnumWithDashes( string value, bool shouldThrow )
        {
            var exception = Record.Exception(() => value.ToEnum<AuthenticatorAttachment>());

            if ( shouldThrow )
            {
                Assert.IsInstanceOfType<ArgumentException>( exception );
            }
            else
            {
                Assert.IsNull( exception );
            }
        }
    }
}