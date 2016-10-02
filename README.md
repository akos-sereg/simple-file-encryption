# Simple File Encryption #
Encryption library that allows you to add extra metadata information to the encrypted file.

### Usage ###
```csharp
// Encrypt file at "filePath", with custom metadata
ISimpleFileEncryptionProvider encryption = new SimpleFileEncryptionProvider();
byte[] content = File.ReadAllBytes(filePath);
byte[] cipher = encryption.Encrypt<dynamic>(new { Filename = "Filename.txt" }, content, "password12345");

// Decrypt cipher and read metadata
dynamic meta;
byte[] decrypted = encryption.Decrypt<dynamic>(cipher, "password12345", out meta); // throws WrongPasswordException
Console.WriteLine(meta.Filename.ToString()); // "Filename.txt"
```

Please note that metadata will not be encrypted in the result of Encrypt method.

