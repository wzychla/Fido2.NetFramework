using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido2NetLib.Test
{
    public class Record
    {
        public static Exception Exception( Action action )
        {
            try
            {
                action();

                return null;
            }
            catch ( Exception ex )
            {
                return ex;
            }
        }
    }
}
