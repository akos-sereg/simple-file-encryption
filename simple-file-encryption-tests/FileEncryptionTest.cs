using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleFileEncryption;
using SimpleFileEncryption.Exceptions;
using SimpleFileEncryption.Model;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace SimpleFileEncryptionTests
{
    [TestClass]
    public class FileEncryptionTest
    {
        #region Testing happy path

        [TestMethod]
        public void FileEncryption_EncryptWithMetaAndDecryptWithMeta_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile<CryptoMetadata>(meta, tempFile, "password123");

            // Assert
            byte[] content = File.ReadAllBytes(tempFile);
            Assert.IsFalse(StructuralComparisons.StructuralEqualityComparer.Equals(content, randomBytes));

            CryptoMetadata decodedMetadata;
            encrypt.DecryptFile(tempFile, "password123", out decodedMetadata);
            byte[] decodedContent = File.ReadAllBytes(tempFile);

            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decodedContent, randomBytes));
            Assert.AreEqual(meta.OriginalFilename, decodedMetadata.OriginalFilename);
            this.AssertTemporaryFilesAreDeleted(tempFile);
        }

        [TestMethod]
        public void FileEncryption_EncryptDecryptWithNoMeta_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile(tempFile, "password123");

            // Assert
            byte[] content = File.ReadAllBytes(tempFile);
            Assert.IsFalse(StructuralComparisons.StructuralEqualityComparer.Equals(content, randomBytes));

            encrypt.DecryptFile(tempFile, "password123");
            byte[] decodedContent = File.ReadAllBytes(tempFile);
            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decodedContent, randomBytes));
            this.AssertTemporaryFilesAreDeleted(tempFile);
        }

        [TestMethod]
        public void FileEncryption_EncryptWithMetaDecryptWithoutMeta_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            CryptoMetadata meta = new CryptoMetadata("sample");
            encrypt.EncryptFile(meta, tempFile, "password123");

            // Assert
            byte[] content = File.ReadAllBytes(tempFile);
            Assert.IsFalse(StructuralComparisons.StructuralEqualityComparer.Equals(content, randomBytes));

            encrypt.DecryptFile(tempFile, "password123");
            byte[] decodedContent = File.ReadAllBytes(tempFile);
            Assert.IsTrue(StructuralComparisons.StructuralEqualityComparer.Equals(decodedContent, randomBytes));
            this.AssertTemporaryFilesAreDeleted(tempFile);
        }

        [TestMethod]
        public void FileEncryption_EncryptWithNoMetaDecryptWithMeta_Throws()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile(tempFile, "password123");
            byte[] content = File.ReadAllBytes(tempFile);
            Assert.IsFalse(StructuralComparisons.StructuralEqualityComparer.Equals(content, randomBytes));

            CryptoMetadata metaOut;
            encrypt.DecryptFile<CryptoMetadata>(tempFile, "password123", out metaOut);

            // Assert
            Assert.IsNull(metaOut);
        }

        #endregion Testing happy path

        #region Testing permissions

        [TestMethod]
        public void FileEncryption_EncryptFileInProtectedFolder_Throws()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            string tempDir = Path.GetDirectoryName(Path.GetTempFileName()) + "/" + Guid.NewGuid().ToString();
            Directory.CreateDirectory(tempDir);

            string tempFile = tempDir + "/file.dat";
            File.WriteAllBytes(tempFile, randomBytes);

            string username = Environment.UserName;
            DirectorySecurity ds = Directory.GetAccessControl(tempDir);
            FileSystemAccessRule fsa = new FileSystemAccessRule(username, FileSystemRights.Write, AccessControlType.Deny);
            ds.AddAccessRule(fsa);
            Directory.SetAccessControl(tempDir, ds);

            // Act
            try
            {
                encrypt.EncryptFile(tempFile, "password123");
                Assert.Fail("Exception should have been thrown");
            }
            catch (FileEncryptionException error)
            {
                Assert.IsNotNull(error.InnerException);
                Assert.AreEqual(typeof(UnauthorizedAccessException), error.InnerException.GetType());
            }
        }

        [TestMethod]
        public void FileEncryption_DecryptFileInProtectedFolder_Throws()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            string tempDir = Path.GetDirectoryName(Path.GetTempFileName()) + "/" + Guid.NewGuid().ToString();
            Directory.CreateDirectory(tempDir);

            string tempFile = tempDir + "/file.dat";
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile(tempFile, "password123");

            string username = Environment.UserName;
            DirectorySecurity ds = Directory.GetAccessControl(tempDir);
            FileSystemAccessRule fsa = new FileSystemAccessRule(username, FileSystemRights.Write, AccessControlType.Deny);
            ds.AddAccessRule(fsa);
            Directory.SetAccessControl(tempDir, ds);

            // Act
            try
            {
                encrypt.DecryptFile(tempFile, "password123");    
                Assert.Fail("Exception should have been thrown");
            }
            catch (FileEncryptionException error)
            {
                Assert.IsNotNull(error.InnerException);
                Assert.AreEqual(typeof(UnauthorizedAccessException), error.InnerException.GetType());
            }
        }

        [TestMethod]
        public void FileEncryption_EncryptMissingFile_Throws()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            string tempDir = Path.GetDirectoryName(Path.GetTempFileName()) + "/" + Guid.NewGuid().ToString();
            Directory.CreateDirectory(tempDir);

            string missingFile = tempDir + "/file.dat";
            
            // Act
            try
            {
                encrypt.EncryptFile(missingFile, "password123");
                Assert.Fail("Exception should have been thrown");
            }
            catch (FileEncryptionException error)
            {
                Assert.AreEqual(typeof(ArgumentException), error.InnerException.GetType());
            }
        }

        [TestMethod]
        public void FileEncryption_DecryptMissingFile_Throws()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            string tempDir = Path.GetDirectoryName(Path.GetTempFileName()) + "/" + Guid.NewGuid().ToString();
            Directory.CreateDirectory(tempDir);

            string missingFile = tempDir + "/file.dat";

            // Act
            try
            {
                encrypt.DecryptFile(missingFile, "password123");
                Assert.Fail("Exception should have been thrown");
            }
            catch (FileEncryptionException error)
            {
                Assert.AreEqual(typeof(ArgumentException), error.InnerException.GetType());
            }
        }

        #endregion Testing permissions

        #region Testing metadata reader

        [TestMethod]
        public void FileEncryption_EncryptWithPublicMeta_ReadMetaWithoutPassword_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile<CryptoMetadata>(meta, tempFile, "password123");

            // Assert
            CryptoMetadata decodedMetadata = encrypt.GetMetadata<CryptoMetadata>(tempFile);
            Assert.AreEqual(meta.OriginalFilename, decodedMetadata.OriginalFilename);
        }

        [TestMethod]
        [ExpectedException(typeof(PasswordRequiredException))]
        public void FileEncryption_EncryptWithProtectedMeta_ReadMetaWithoutPassword_Throws()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile<CryptoMetadata>(meta, tempFile, "password123", true);

            // Assert
            CryptoMetadata decodedMetadata = encrypt.GetMetadata<CryptoMetadata>(tempFile);
        }

        [TestMethod]
        public void FileEncryption_EncryptWithProtectedMeta_ReadMetaWithPassword_Works()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            CryptoMetadata meta = new CryptoMetadata("sample");

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile<CryptoMetadata>(meta, tempFile, "password123", true);

            // Assert
            CryptoMetadata decodedMetadata = encrypt.GetMetadata<CryptoMetadata>(tempFile, "password123");
            Assert.AreEqual(meta.OriginalFilename, decodedMetadata.OriginalFilename);
        }

        #endregion Testing metadata reader

        #region Testing isEncrypted

        [TestMethod]
        public void FileEncryption_IsEncrypted_WorksForCipher()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            encrypt.EncryptFile(tempFile, "password123");

            bool isEncrypted = encrypt.IsEncrypted(tempFile);

            // Assert
            Assert.IsTrue(isEncrypted);
        }

        [TestMethod]
        public void FileEncryption_IsEncrypted_WorksNormalFile()
        {
            // Arrange
            ISimpleFileEncryptionProvider encrypt = new SimpleFileEncryptionProvider();

            byte[] randomBytes = new byte[1024];
            new Random().NextBytes(randomBytes);

            // Act
            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, randomBytes);
            
            bool isEncrypted = encrypt.IsEncrypted(tempFile);

            // Assert
            Assert.IsFalse(isEncrypted);
        }

        #endregion Testing isEncrypted

        private void AssertTemporaryFilesAreDeleted(string filePath)
        {
            Assert.IsFalse(File.Exists(filePath + ".orig"), ".orig temporary file left there");
            Assert.IsFalse(File.Exists(filePath + ".encoded"), ".encoded temporary file left there");
            Assert.IsFalse(File.Exists(filePath + ".decoded"), ".decoded temporary file left there");
        }
    }
}
