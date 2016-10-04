using System;
using System.Collections;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleFileEncryption.Model;
using SimpleFileEncryption;
using SimpleFileEncryption.Exceptions;

namespace SimpleFileEncryptionTests
{
    [TestClass]
    public class DataEncryptionTest
    {
        [TestMethod]
        public void DataEncryption_EncryptDecrypt_Works()
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
        public void DataEncryption_EncryptDecryptWithDynamicObject_Works()
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
            Console.WriteLine();
        }

        [TestMethod]
        public void DataEncryption_EncryptDecryptWithNull_Works()
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
        public void DataEncryption_EncryptDecryptWithNoData_Works()
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
        public void DataEncryption_EncryptWithMetaDecryptWithNoMeta_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);
            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt<CryptoMetadata>(meta, randomBytes, "Sample Password");
            byte[] decrypted = encrypt.Decrypt(cipher, "Sample Password");

            // Assert
            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decrypted, randomBytes));
        }

        [TestMethod]
        [ExpectedException(typeof(WrongPasswordException))]
        public void DataEncryption_DecryptWithInvalidPassword_ThrowsException()
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

        [TestMethod]
        public void DataEncryption_EncryptMetadataAswell_DecryptWorks()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt(meta, randomBytes, "Sample Password", true);
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
        public void DataEncryption_EncryptMetadataAswell_GetMetaWorks()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt(meta, randomBytes, "Sample Password", true);
            CryptoMetadata decryptedMeta = encrypt.GetMetadata<CryptoMetadata>(cipher, "Sample Password");

            // Assert
            Assert.IsNotNull(decryptedMeta);
            Assert.AreEqual(meta.Author, decryptedMeta.Author);
            Assert.AreEqual(meta.AuthorDomain, decryptedMeta.AuthorDomain);
            Assert.AreEqual(meta.EncryptedAt, decryptedMeta.EncryptedAt);
            Assert.AreEqual(meta.IpAddress, decryptedMeta.IpAddress);
            Assert.AreEqual(meta.MachineName, decryptedMeta.MachineName);
            Assert.AreEqual(meta.OriginalFilename, decryptedMeta.OriginalFilename);
        }

        [TestMethod]
        [ExpectedException(typeof(PasswordRequiredException))]
        public void DataEncryption_EncryptMetadataAswell_GetMetaWithNoPassword()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt(meta, randomBytes, "Sample Password", true);
            encrypt.GetMetadata<CryptoMetadata>(cipher);
        }

        [TestMethod]
        [ExpectedException(typeof(WrongPasswordException))]
        public void DataEncryption_EncryptMetadataAswell_GetMetaWithBadPassword()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            byte[] cipher = encrypt.Encrypt(meta, randomBytes, "Sample Password", true);
            encrypt.GetMetadata<CryptoMetadata>(cipher, "Invalid Password");
        }

        [TestMethod]
        public void DataEncryption_IsEncryptedForRandom_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act 
            bool isEncrypted = encrypt.IsEncrypted(randomBytes);

            // Assert
            Assert.IsFalse(isEncrypted);
        }

        [TestMethod]
        public void DataEncryption_IsEncryptedForCipher_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);
            byte[] cipher = encrypt.Encrypt(randomBytes, "Sample Password");

            // Act 
            bool isEncrypted = encrypt.IsEncrypted(cipher);

            // Assert
            Assert.IsTrue(isEncrypted);
        }
    }
}
