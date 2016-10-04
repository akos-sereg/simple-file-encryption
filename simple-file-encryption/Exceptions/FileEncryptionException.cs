using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleFileEncryption.Exceptions
{
    public class FileEncryptionException : Exception
    {
        public FileEncryptionException(string message)
            : base(message)
        {
        }

        public FileEncryptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
