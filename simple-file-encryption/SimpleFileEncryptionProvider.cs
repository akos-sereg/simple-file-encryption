using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Configuration;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using SimpleFileEncryption.Cryptography;
using SimpleFileEncryption.Exceptions;

namespace SimpleFileEncryption
{
    public class SimpleFileEncryptionProvider : ISimpleFileEncryptionProvider
    {
        /// <summary>
        /// Cryptography operations
        /// </summary>
        private readonly IDataCryptoProvider cryptoProvider = new BinaryCryptoProvider();

        /// <summary>
        /// Metadata Length positioning
        /// </summary>
        private readonly string MetaLengthKey = "MetaLength";

        /// <summary>
        /// Encrypted files are starting with these header bytes
        /// </summary>
        private readonly byte[] header = { 0xFA, 0x15, 0xEC, 0x0D, 0xE5 };

        #region Data Encryption

        public byte[] Encrypt<T>(T metadata, byte[] content, string password, bool encryptMetadata = false)
        {
            if (metadata == null)
            {
                metadata = default(T);
            }

            List<byte> data = new List<byte>();
            data.AddRange(header);

            string meta = JsonConvert.SerializeObject(metadata);
            
            if (encryptMetadata)
            {
                byte[] encryptedMeta = this.cryptoProvider.Encrypt(Encoding.UTF8.GetBytes(meta), password);
                data.AddRange(Encoding.UTF8.GetBytes(MetaLengthKey + ":" + encryptedMeta.Length + "|"));
                data.AddRange(encryptedMeta);
            }
            else
            {    
                data.AddRange(Encoding.UTF8.GetBytes(MetaLengthKey + ":" + meta.Length + "|" + meta));    
            }
            
            byte[] cipher = this.cryptoProvider.Encrypt(content, password);
            data.AddRange(cipher);

            return data.ToArray();
        }

        public byte[] Decrypt<T>(byte[] content, string password, out T metadata)
        {
            long metaLength;
            metadata = this.GetMetadataInner<T>(content, password, out metaLength);
            long dataOffset = header.Length + (MetaLengthKey + ":|").Length + metaLength.ToString().Length + metaLength;

            var cipher = new List<byte>();
            for (var i = dataOffset; i != content.Length; i++)
            {
                cipher.Add(content[i]);
            }

            try
            {
                return this.cryptoProvider.Decrypt(cipher.ToArray(), password);
            }
            catch (CryptographicException)
            {
                throw new WrongPasswordException("Wrong password provided", password);
            }
        }

        public byte[] Encrypt(byte[] content, string password)
        {
            return this.Encrypt<dynamic>(null, content, password);
        }

        public byte[] Decrypt(byte[] content, string password)
        {
            dynamic meta;
            return this.Decrypt(content, password, out meta);
        }

        #endregion

        #region Reading Metadata

        public T GetMetadata<T>(byte[] content)
        {
            return this.GetMetadata<T>(content, null);
        }

        public T GetMetadata<T>(byte[] content, string password)
        {
            long metaLength;
            return this.GetMetadataInner<T>(content, password, out metaLength);
        }

        public T GetMetadata<T>(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new FileEncryptionException("File Path is missing", new ArgumentNullException("filePath"));
            }

            if (!File.Exists(filePath))
            {
                throw new FileEncryptionException("File does not exist: " + filePath, new ArgumentException("filePath"));
            }

            byte[] encryptedContent;
            try
            {
                encryptedContent = File.ReadAllBytes(filePath);
                return this.GetMetadata<T>(encryptedContent);
            }
            catch (PathTooLongException error)
            {
                throw new FileEncryptionException("Path too long: " + filePath, error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new FileEncryptionException("Can not read file: " + filePath, error);
            }
        }

        public T GetMetadata<T>(string filePath, string password)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new FileEncryptionException("File Path is missing", new ArgumentNullException("filePath"));
            }

            if (!File.Exists(filePath))
            {
                throw new FileEncryptionException("File does not exist: " + filePath, new ArgumentException("filePath"));
            }

            byte[] encryptedContent;
            try
            {
                encryptedContent = File.ReadAllBytes(filePath);
                return this.GetMetadata<T>(encryptedContent, password);
            }
            catch (PathTooLongException error)
            {
                throw new FileEncryptionException("Path too long: " + filePath, error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new FileEncryptionException("Can not read file: " + filePath, error);
            }
        }

        #endregion

        # region File Encryption

        public void EncryptFile<T>(T metadata, string filePath, string password, bool encryptMetadata = false)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new FileEncryptionException("File Path is missing", new ArgumentNullException("filePath"));
            }

            if (!File.Exists(filePath))
            {
                throw new FileEncryptionException("File does not exist: " + filePath, new ArgumentException("filePath"));
            }

            byte[] cipher = this.Encrypt<T>(metadata, File.ReadAllBytes(filePath), password, encryptMetadata);

            string encodedTempPath = filePath + ".encoded";
            string originalTempPath = filePath + ".orig";

            try
            {
                File.WriteAllBytes(encodedTempPath, cipher);
            }
            catch (PathTooLongException error)
            {
                throw new FileEncryptionException("Destination path for temp location is too long (" + encodedTempPath + ")", error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new FileEncryptionException("Can not write file, permission denied:" + encodedTempPath, error);
            }

            File.Move(filePath, originalTempPath);
            File.Move(encodedTempPath, filePath);
            File.Delete(originalTempPath);
        }

        public void EncryptFile(string filePath, string password)
        {
            this.EncryptFile<dynamic>(null, filePath, password);
        }

        public void DecryptFile(string filePath, string password)
        {
            dynamic metadata;
            this.DecryptFile(filePath, password, out metadata);
        }

        public void DecryptFile<T>(string filePath, string password, out T metadata)
        {
            metadata = default(T);
            if (string.IsNullOrEmpty(filePath))
            {
                throw new FileEncryptionException("File Path is missing", new ArgumentNullException("filePath"));
            }

            if (!File.Exists(filePath))
            {
                throw new FileEncryptionException("File does not exist: " + filePath, new ArgumentException("filePath"));
            }

            byte[] encryptedContent;
            try
            {
                encryptedContent = File.ReadAllBytes(filePath);
            }
            catch (PathTooLongException error)
            {
                throw new FileEncryptionException("Path too long: " + filePath, error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new FileEncryptionException("Can not read file: " + filePath, error);
            }

            byte[] originalContent = this.Decrypt<T>(encryptedContent, password, out metadata);

            string decodedTempPath = filePath + ".decoded";
            string originalTempPath = filePath + ".orig";

            try
            {
                File.WriteAllBytes(decodedTempPath, originalContent);
            }
            catch (PathTooLongException error)
            {
                throw new FileEncryptionException("Destination path for temp location is too long (" + decodedTempPath + ")", error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new FileEncryptionException("Can not write file, permission denied:" + decodedTempPath, error);
            }

            File.Move(filePath, originalTempPath);
            File.Move(decodedTempPath, filePath);
            File.Delete(originalTempPath);
        }

        #endregion

        private T GetMetadataInner<T>(byte[] content, string password, out long metaLength)
        {
            if (!this.IsEncrypted(content))
            {
                metaLength = 0;
                return default(T);
            }

            long metaStartOffset;
            metaLength = this.GetMetaLength(content, out metaStartOffset);
            byte[] meta = this.GetMetadata(content, metaStartOffset, metaLength);

            try
            {
                return JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(meta));
            }
            catch (JsonReaderException)
            {
                if (string.IsNullOrEmpty(password))
                {
                    throw new PasswordRequiredException("Metadata is encrypted, password is required but missing.");
                }

                try
                {
                    byte[] decryptedMetadata = this.cryptoProvider.Decrypt(meta, password);
                    return JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(decryptedMetadata));
                }
                catch (CryptographicException)
                {
                    throw new WrongPasswordException("Unable to read metadata from cipher", password);
                }
            }
        }

        private bool IsEncrypted(byte[] content)
        {
            if (content.Length < header.Length)
            {
                return false;
            }

            for (var i = 0; i != header.Length; i++)
            {
                if (content[i] != header[i])
                {
                    return false;
                }
            }

            return true;
        }

        private long GetMetaLength(byte[] content, out long metaStartOffset)
        {
            var start = header.Length + (MetaLengthKey + ":").Length;
            var lengthBytes = new List<byte>();

            metaStartOffset = -1;
            for (var i = start; i != start + 200; i++)
            {
                if (content[i] == '|')
                {
                    metaStartOffset = i + 1;
                    break;
                }

                lengthBytes.Add(content[i]);
            }

            var length = Encoding.UTF8.GetString(lengthBytes.ToArray());
            return long.Parse(length);
        }

        private byte[] GetMetadata(byte[] content, long offset, long length)
        {
            if (offset == -1)
            {
                throw new Exception("Offset is not defined correctly");
            }

            var metaContent = new List<byte>();

            for (var i = offset; i != offset + length; i++)
            {
                metaContent.Add(content[i]);
            }

            return metaContent.ToArray();
        }
    }
}
