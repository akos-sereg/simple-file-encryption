﻿namespace SimpleFileEncryption
{
    public interface ISimpleFileEncryptionProvider
    {
        /// <summary>
        /// Encrypt data with specified <see cref="password"/>.
        /// </summary>
        /// <typeparam name="T">Generic metadata type</typeparam>
        /// <param name="metadata">Metadata (can be an instance of dynamic, CryptoMeta, or anything else)</param>
        /// <param name="content">Content that should be encrypted</param>
        /// <param name="password">Result will be encrypted with this password</param>
        /// <param name="encryptMetadata">If set to true, metadata will be encrypted as well</param>
        /// <returns>Metadata and encrypted data. Please note that metadata will not be encrypted.</returns>
        byte[] Encrypt<T>(T metadata, byte[] content, string password, bool encryptMetadata = false);

        /// <summary>
        /// Decrypt data, using specified <see cref="password"/>.
        /// </summary>
        /// <typeparam name="T">Metadata (can be an instance of dynamic, CryptoMeta, or anything else)</typeparam>
        /// <param name="content">Result of the Encrypt method</param>
        /// <param name="password">Content will be decrypted using this password</param>
        /// <param name="metadata">Metadata that was passed when Encrypt was called</param>
        /// <returns>Decrypted data</returns>
        byte[] Decrypt<T>(byte[] content, string password, out T metadata);

        /// <summary>
        /// Encrypt data with specified <see cref="password"/>.
        /// </summary>
        /// <param name="content">Content that should be encrypted</param>
        /// <param name="password">Result will be encrypted with this password</param>
        /// <returns>Encrypted data</returns>
        byte[] Encrypt(byte[] content, string password);

        /// <summary>
        /// Decrypt data, using specified <see cref="password"/>.
        /// </summary>
        /// <param name="content">Result of the Encrypt method</param>
        /// <param name="password">Content will be decrypted using this password</param>
        /// <returns>Decrypted data</returns>
        byte[] Decrypt(byte[] content, string password);

        /// <summary>
        /// Get metadata of encrypted data
        /// </summary>
        /// <typeparam name="T">Metadata (can be an instance of dynamic, CryptoMeta, or anything else)</typeparam>
        /// <param name="cipher">Result of Encrypt method</param>
        /// <returns>Metadata that was passed when Encrypt was called (with encryptMetadata = false, otherwise it would throw PasswordRequiredException)</returns>
        T GetMetadata<T>(byte [] cipher);

        /// <summary>
        /// Get metadata of encrypted data
        /// </summary>
        /// <typeparam name="T">Metadata (can be an instance of dynamic, CryptoMeta, or anything else)</typeparam>
        /// <param name="cipher">Result of Encrypt method</param>
        /// <param name="password">Password</param>
        /// <returns>Metadata that was passed when Encrypt was called</returns>
        T GetMetadata<T>(byte[] cipher, string password);
    }
}
