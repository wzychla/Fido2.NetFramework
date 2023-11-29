using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.VisualStudio.TestTools.UnitTesting
{
    public class CollectionAssertExtensions
    {
        public static void All<T>( IEnumerable<T> collection, Predicate<T> predicate )
        {
            foreach ( var e in collection )
            {
                Assert.IsTrue( predicate( e ) );
            }
        }
    }
}
