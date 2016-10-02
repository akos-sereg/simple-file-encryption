using System;
using System.Collections;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleFileEncryption.Model;
using SimpleFileEncryption;

namespace SimpleFileEncryptionTests
{
    [TestClass]
    public class SimpleFileEncryptionProviderTest
    {
        [TestMethod]
        public void SimpleFileEncryption_EncryptDecrypt_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt(meta, randomBytes, "Sample Password");
            CryptoMetadata decryptedMeta;
            byte[] decrypted = encrypt.Decrypt(cipher, "Sample Password", out decryptedMeta);

            // Assert
            Assert.IsNotNull(decryptedMeta);
            Assert.AreEqual(meta.Author, decryptedMeta.Author);
            Assert.AreEqual(meta.AuthorDomain, decryptedMeta.AuthorDomain);
            Assert.AreEqual(meta.EncryptedAt, decryptedMeta.EncryptedAt);
            Assert.AreEqual(meta.IpAddress, decryptedMeta.IpAddress);
            Assert.AreEqual(meta.MachineName, decryptedMeta.MachineName);
            Assert.AreEqual(meta.OriginalFilename, decryptedMeta.OriginalFilename);

            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decrypted, randomBytes));
        }

        [TestMethod]
        public void SimpleFileEncryption_EncryptDecryptWithDynamicObject_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            dynamic meta = new { Filename = "Filename.txt", SomeParameter = "12345" };

            // Act
            byte[] cipher = encrypt.Encrypt<dynamic>(meta, randomBytes, "Sample Password");
            dynamic decryptedMeta;
            byte[] decrypted = encrypt.Decrypt(cipher, "Sample Password", out decryptedMeta);

            // Assert
            Assert.IsNotNull(decryptedMeta);
            Assert.AreEqual(meta.Filename.ToString(), decryptedMeta.Filename.ToString());
            Assert.AreEqual(meta.SomeParameter.ToString(), decryptedMeta.SomeParameter.ToString());

            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decrypted, randomBytes));
        }

        [TestMethod]
        public void SimpleFileEncryption_EncryptDecryptWithNull_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            byte[] cipher = encrypt.Encrypt<dynamic>(null, randomBytes, "Sample Password");
            dynamic decryptedMeta;
            byte[] decrypted = encrypt.Decrypt(cipher, "Sample Password", out decryptedMeta);

            // Assert
            Assert.IsNull(decryptedMeta);

            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decrypted, randomBytes));
        }

        [TestMethod]
        public void SimpleFileEncryption_EncryptDecryptWithNoData_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            byte[] cipher = encrypt.Encrypt(randomBytes, "Sample Password");
            byte[] decrypted = encrypt.Decrypt(cipher, "Sample Password");

            // Assert
            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decrypted, randomBytes));
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void SimpleFileEncryption_DecryptWithInvalidPassword_ThrowsException()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt(meta, randomBytes, "Sample Password");
            CryptoMetadata decryptedMeta;
            encrypt.Decrypt(cipher, "Invalid Password", out decryptedMeta);
        }
    }
}
