namespace SimpleFileEncryption.Cryptography
{
    public interface IDataCryptoProvider
    {
        byte[] Encrypt(byte[] data, string password);

        byte[] Decrypt(byte[] cipher, string password);
    }
}
