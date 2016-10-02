using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace SimpleFileEncryption.Cryptography
{
    public class BinaryCryptoProvider : IDataCryptoProvider
    {
        private const int Keysize = 256;

        private const int DerivationIterations = 1000;

        public byte[] Encrypt(byte[] data, string passPhrase)
        {
            var saltStringBytes = GetRandomEntropy();
            var ivStringBytes = GetRandomEntropy();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(data, 0, data.Length);
                                cryptoStream.FlushFinalBlock();

                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return cipherTextBytes;
                            }
                        }
                    }
                }
            }
        }

        public byte[] Decrypt(byte[] cipher, string passPhrase)
        {
            var saltStringBytes = cipher.Take(Keysize / 8).ToArray();
            var ivStringBytes = cipher.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            var cipherTextBytes = cipher.Skip((Keysize / 8) * 2).Take(cipher.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();

                                var result = new byte[decryptedByteCount];
                                Buffer.BlockCopy(plainTextBytes, 0, result, 0, decryptedByteCount);

                                return result;
                            }
                        }
                    }
                }
            }
        }

        private static byte[] GetRandomEntropy()
        {
            var randomBytes = new byte[32]; 
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }

            return randomBytes;
        }
    }
}
