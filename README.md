# Simple File Encryption #
Encryption library that allows you to add extra metadata information to the encrypted file.

[![Version](https://img.shields.io/nuget/v/SimpleFileEncryption.svg)](https://www.nuget.org/packages/SimpleFileEncryption)

### Install ###
```csharp
PM> Install-Package SimpleFileEncryption
```

### Usage ###
```csharp
string inputFile = "C:\test.txt";
string encryptedFile = "C:\test.encrypted.txt";

// Encrypt file with custom metadata
var encryption = new SimpleFileEncryptionProvider();
byte[] cipher = encryption.Encrypt<dynamic>(
    new { Filename = "Filename.txt" }, 
    File.ReadAllBytes(inputFile), 
    "passwd");
File.WriteAllBytes(encryptedFile, cipher);

// Decrypt file content and read metadata
dynamic meta;
byte[] decrypted = encryption.Decrypt<dynamic>(
    File.ReadAllBytes(encryptedFile), 
    "passwd",
    out meta); 
Console.WriteLine(meta.Filename.ToString()); // "Filename.txt"
Console.WriteLine(Encoding.UTF8.GetString(decrypted)); // original content of test.txt
```

Please note that metadata will not be encrypted in the result of Encrypt method, by default. You can set *encryptMetadata = true* when calling Encrypt, if you want to secure metadata block as well.
