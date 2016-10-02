using System;

namespace SimpleFileEncryption.Exceptions
{
    public class PasswordRequiredException : Exception
    {
        public PasswordRequiredException(string message)
            : base(message)
        {
            
        }
    }
}
