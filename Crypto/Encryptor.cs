using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NiceCrypt.Models;
using NiceCrypt.Utils;

namespace NiceCrypt.Crypto
{
    public static class Encryptor
    {
        const string Magic = "NICE";
        const byte Version2 = 2;
        const byte Version3 = 3;
        const int NonceSize = 12;
        const int TagSize = 16;
        const int DefaultChunkSize = 4 * 1024 * 1024;
        const int Pbkdf2Iterations = 200000;

        public static void Execute(
            string inputPath,
            string? keyFilePath,
            Action<long, long>? progress = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);

            byte[] key;
            byte[] nonce = SecureRandom.GenerateBytes(NonceSize); // 96-bit nonce
            bool saveKey = false;

            // Determine Key Strategy
            if (string.IsNullOrEmpty(keyFilePath))
            {
                key = SecureRandom.GenerateBytes(32); // 256-bit key
                keyFilePath = inputPath + ".key";
                saveKey = true;
            }
            else
            {
                if (File.Exists(keyFilePath))
                {
                    var existingKeyFile = JsonSerializer.Deserialize<KeyFile>(File.ReadAllText(keyFilePath));
                    if (existingKeyFile == null || string.IsNullOrEmpty(existingKeyFile.Key))
                        throw new CryptographicException("Invalid key file format.");
                    
                    key = Convert.FromBase64String(existingKeyFile.Key);
                }
                else
                {
                    key = SecureRandom.GenerateBytes(32);
                    saveKey = true;
                }
            }

            // Save Key File if generated
            if (saveKey)
            {
                var keyData = new KeyFile
                {
                    Algorithm = "AES-256-GCM",
                    Key = Convert.ToBase64String(key),
                    Created = DateTime.UtcNow
                };

                string json = JsonSerializer.Serialize(keyData, new JsonSerializerOptions { WriteIndented = true });
                FileHelpers.AtomicWrite(keyFilePath, Encoding.UTF8.GetBytes(json));
            }

            string outputPath = inputPath + ".nice";
            long totalBytes = new FileInfo(inputPath).Length;
            string tempPath = outputPath + ".tmp";

            try
            {
                using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var outputStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var writer = new BinaryWriter(outputStream, Encoding.UTF8, leaveOpen: true))
                using (var aes = new AesGcm(key, TagSize))
                {
                    // Header: magic(4), version(1), chunkSize(4), originalLength(8)
                    writer.Write(Encoding.ASCII.GetBytes(Magic));
                    writer.Write(Version2);
                    writer.Write(DefaultChunkSize);
                    writer.Write(totalBytes);

                    byte[] plaintext = new byte[DefaultChunkSize];
                    byte[] ciphertext = new byte[DefaultChunkSize];
                    byte[] tag = new byte[TagSize];

                    long processed = 0;
                    int read;
                    while ((read = inputStream.Read(plaintext, 0, plaintext.Length)) > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        byte[] chunkNonce = SecureRandom.GenerateBytes(NonceSize);

                        aes.Encrypt(
                            chunkNonce,
                            plaintext.AsSpan(0, read),
                            ciphertext.AsSpan(0, read),
                            tag
                        );

                        writer.Write(chunkNonce);
                        writer.Write(read); // ciphertext length
                        writer.Write(ciphertext, 0, read);
                        writer.Write(tag, 0, tag.Length);

                        processed += read;
                        progress?.Invoke(processed, totalBytes);
                    }
                }
            }
            catch
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
                throw;
            }

            FileHelpers.AtomicMove(tempPath, outputPath);
            
            // Cleanup
            Array.Clear(key, 0, key.Length);
            Array.Clear(nonce, 0, nonce.Length);
        }

        public static void ExecuteWithPassword(
            string inputPath,
            char[] password,
            Action<long, long>? progress = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);

            byte[] salt = SecureRandom.GenerateBytes(16);
            byte[] key = DeriveKey(password, salt, Pbkdf2Iterations);

            string outputPath = inputPath + ".nice";
            long totalBytes = new FileInfo(inputPath).Length;
            string tempPath = outputPath + ".tmp";

            try
            {
                using (var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var outputStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var writer = new BinaryWriter(outputStream, Encoding.UTF8, leaveOpen: true))
                using (var aes = new AesGcm(key, TagSize))
                {
                    // Header: magic(4), version(1), chunkSize(4), originalLength(8), kdf(1), iterations(4), saltLen(1), salt(N)
                    writer.Write(Encoding.ASCII.GetBytes(Magic));
                    writer.Write(Version3);
                    writer.Write(DefaultChunkSize);
                    writer.Write(totalBytes);
                    writer.Write((byte)1); // KDF id: 1 = PBKDF2-SHA256
                    writer.Write(Pbkdf2Iterations);
                    writer.Write((byte)salt.Length);
                    writer.Write(salt);

                    byte[] plaintext = new byte[DefaultChunkSize];
                    byte[] ciphertext = new byte[DefaultChunkSize];
                    byte[] tag = new byte[TagSize];

                    long processed = 0;
                    int read;
                    while ((read = inputStream.Read(plaintext, 0, plaintext.Length)) > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        byte[] chunkNonce = SecureRandom.GenerateBytes(NonceSize);

                        aes.Encrypt(
                            chunkNonce,
                            plaintext.AsSpan(0, read),
                            ciphertext.AsSpan(0, read),
                            tag
                        );

                        writer.Write(chunkNonce);
                        writer.Write(read);
                        writer.Write(ciphertext, 0, read);
                        writer.Write(tag, 0, tag.Length);

                        processed += read;
                        progress?.Invoke(processed, totalBytes);
                    }
                }
            }
            catch
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
                throw;
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                Array.Clear(salt, 0, salt.Length);
            }

            FileHelpers.AtomicMove(tempPath, outputPath);
        }

        static byte[] DeriveKey(char[] password, byte[] salt, int iterations)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            try
            {
                using (var kdf = new System.Security.Cryptography.Rfc2898DeriveBytes(
                    passwordBytes,
                    salt,
                    iterations,
                    System.Security.Cryptography.HashAlgorithmName.SHA256))
                {
                    return kdf.GetBytes(32);
                }
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }
    }
}
