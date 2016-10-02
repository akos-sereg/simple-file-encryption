using System;

namespace SimpleFileEncryption.Exceptions
{
    public class WrongPasswordException : Exception
    {
        public string Password { get; private set; }

        public WrongPasswordException(string message, string password)
            : base(message)
        {
            this.Password = password;
        }
    }
}
