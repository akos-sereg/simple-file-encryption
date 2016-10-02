using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using SimpleFileEncryption.Cryptography;

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

        public byte[] Encrypt<T>(T metadata, byte[] content, string password)
        {
            if (metadata == null)
            {
                metadata = default(T);
            }

            List<byte> data = new List<byte>();

            string meta = JsonConvert.SerializeObject(metadata);
            data.AddRange(header);
            data.AddRange(Encoding.UTF8.GetBytes(MetaLengthKey + ":" + meta.Length + "|" + meta));

            byte[] cipher = this.cryptoProvider.Encrypt(content, password);
            data.AddRange(cipher);

            return data.ToArray();
        }

        public byte[] Decrypt<T>(byte[] content, string password, out T metadata)
        {
            metadata = this.GetMetadata<T>(content);
            long metaLength = JsonConvert.SerializeObject(metadata).Length;
            long dataOffset = header.Length + (MetaLengthKey + ":|").Length + metaLength.ToString().Length + metaLength;

            var cipher = new List<byte>();
            for (var i = dataOffset; i != content.Length; i++)
            {
                cipher.Add(content[i]);
            }

            return this.cryptoProvider.Decrypt(cipher.ToArray(), password);
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

        public T GetMetadata<T>(string filePath)
        {
            byte[] content = File.ReadAllBytes(filePath);
            return this.GetMetadata<T>(content);
        }

        private T GetMetadata<T>(byte[] content)
        {
            if (!this.IsEncrypted(content))
            {
                return default(T);
            }

            long metaStartOffset;
            long metaLength = this.GetMetaLength(content, out metaStartOffset);
            string serializedMeta = this.GetMetadata(content, metaStartOffset, metaLength);

            return JsonConvert.DeserializeObject<T>(serializedMeta);
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

        private string GetMetadata(byte[] content, long offset, long length)
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

            return Encoding.UTF8.GetString(metaContent.ToArray());
        }
    }
}
