using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NiceCrypt.Models;
using NiceCrypt.Utils;

namespace NiceCrypt.Crypto
{
    public static class Decryptor
    {
        const string Magic = "NICE";
        const byte Version2 = 2;
        const byte Version3 = 3;
        const int NonceSize = 12;
        const int TagSize = 16;
        const int KeySize = 32;

        public static void Verify(
            string encryptedPath,
            string keyFilePath,
            System.Threading.CancellationToken cancellationToken = default)
        {
            DecryptInternal(encryptedPath, keyFilePath, null, writeOutput: false, cancellationToken);
        }

        public static void VerifyWithPassword(
            string encryptedPath,
            char[] password,
            System.Threading.CancellationToken cancellationToken = default)
        {
            DecryptInternal(encryptedPath, string.Empty, null, writeOutput: false, cancellationToken, password);
        }

        public static void Execute(
            string encryptedPath,
            string keyFilePath,
            Action<long, long>? progress = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            DecryptInternal(encryptedPath, keyFilePath, progress, writeOutput: true, cancellationToken);
        }

        public static void ExecuteWithPassword(
            string encryptedPath,
            char[] password,
            Action<long, long>? progress = null,
            System.Threading.CancellationToken cancellationToken = default)
        {
            DecryptInternal(encryptedPath, string.Empty, progress, writeOutput: true, cancellationToken, password);
        }

        static void DecryptInternal(
            string encryptedPath,
            string keyFilePath,
            Action<long, long>? progress,
            bool writeOutput,
            System.Threading.CancellationToken cancellationToken,
            char[]? passwordOverride = null)
        {
            if (!File.Exists(encryptedPath))
                throw new FileNotFoundException("Encrypted file not found.", encryptedPath);

            byte[] key = Array.Empty<byte>();
            if (passwordOverride == null || passwordOverride.Length == 0)
            {
                if (!File.Exists(keyFilePath))
                    throw new FileNotFoundException("Key file not found.", keyFilePath);

                string json = File.ReadAllText(keyFilePath);
                var keyData = JsonSerializer.Deserialize<KeyFile>(json);

                if (keyData == null || keyData.Algorithm != "AES-256-GCM")
                    throw new CryptographicException("Invalid or unsupported key file.");

                key = Convert.FromBase64String(keyData.Key);
            }

            try
            {
                using (var input = new FileStream(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true))
                {
                    byte[] magicBytes = reader.ReadBytes(4);
                    string magic = Encoding.ASCII.GetString(magicBytes);

                    if (magic == Magic)
                    {
                        byte version = reader.ReadByte();
                        if (version == Version2)
                        {
                            if (key.Length != KeySize)
                                throw new CryptographicException("Key file required for this file.");
                            DecryptV2(reader, input, encryptedPath, key, progress, writeOutput, cancellationToken);
                            return;
                        }
                        if (version == Version3)
                        {
                            if (passwordOverride == null || passwordOverride.Length == 0)
                                throw new CryptographicException("Password required for this file.");
                            DecryptV3(reader, input, encryptedPath, passwordOverride, progress, writeOutput, cancellationToken);
                            return;
                        }
                        throw new CryptographicException("Unsupported .nice format version.");
                    }
                }

                if (passwordOverride != null && passwordOverride.Length > 0)
                    throw new CryptographicException("Password not supported for legacy format.");
                DecryptV1(encryptedPath, key, progress, writeOutput, cancellationToken);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException(writeOutput
                    ? "Decryption failed. Invalid key or corrupted file."
                    : "Verification failed. Invalid key or corrupted file.");
            }
            finally
            {
                if (key.Length > 0) Array.Clear(key, 0, key.Length);
            }
        }

        static void DecryptV2(
            BinaryReader reader,
            FileStream input,
            string encryptedPath,
            byte[] key,
            Action<long, long>? progress,
            bool writeOutput,
            System.Threading.CancellationToken cancellationToken)
        {
            int chunkSize = reader.ReadInt32();
            long originalLength = reader.ReadInt64();

            Stream output = Stream.Null;
            string outputPath = string.Empty;
            string tempPath = string.Empty;

            if (writeOutput)
            {
                outputPath = encryptedPath.EndsWith(".nice")
                    ? encryptedPath.Substring(0, encryptedPath.Length - 5)
                    : encryptedPath + ".decrypted";
                tempPath = outputPath + ".tmp";
                output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None);
            }

            try
            {
                using (output)
                using (var aes = new AesGcm(key, TagSize))
                {
                    byte[] plaintext = new byte[chunkSize];
                    byte[] ciphertext = new byte[chunkSize];
                    byte[] tag = new byte[TagSize];

                    long processed = 0;

                    while (input.Position < input.Length)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        byte[] nonce = reader.ReadBytes(NonceSize);
                        if (nonce.Length != NonceSize)
                            throw new CryptographicException("File corrupted or truncated.");

                        int cipherLen = reader.ReadInt32();
                        if (cipherLen < 0 || cipherLen > chunkSize)
                            throw new CryptographicException("File corrupted or invalid chunk size.");

                        int read = reader.Read(ciphertext, 0, cipherLen);
                        if (read != cipherLen)
                            throw new CryptographicException("File corrupted or truncated.");

                        int tagRead = reader.Read(tag, 0, TagSize);
                        if (tagRead != TagSize)
                            throw new CryptographicException("File corrupted or truncated.");

                        aes.Decrypt(
                            nonce,
                            ciphertext.AsSpan(0, cipherLen),
                            tag,
                            plaintext.AsSpan(0, cipherLen)
                        );

                        if (writeOutput)
                        {
                            output.Write(plaintext, 0, cipherLen);
                        }

                        processed += cipherLen;
                        progress?.Invoke(processed, originalLength);
                    }

                    if (processed != originalLength)
                        throw new CryptographicException("File corrupted or length mismatch.");
                }
            }
            catch
            {
                if (writeOutput && !string.IsNullOrEmpty(tempPath) && File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
                throw;
            }

            if (writeOutput)
            {
                FileHelpers.AtomicMove(tempPath, outputPath);
            }
        }

        static void DecryptV3(
            BinaryReader reader,
            FileStream input,
            string encryptedPath,
            char[] password,
            Action<long, long>? progress,
            bool writeOutput,
            System.Threading.CancellationToken cancellationToken)
        {
            int chunkSize = reader.ReadInt32();
            long originalLength = reader.ReadInt64();
            byte kdfId = reader.ReadByte();
            int iterations = reader.ReadInt32();
            byte saltLen = reader.ReadByte();
            byte[] salt = reader.ReadBytes(saltLen);

            if (kdfId != 1)
                throw new CryptographicException("Unsupported KDF.");

            byte[] key = DeriveKey(password, salt, iterations);
            try
            {
                Stream output = Stream.Null;
                string outputPath = string.Empty;
                string tempPath = string.Empty;

                if (writeOutput)
                {
                    outputPath = encryptedPath.EndsWith(".nice")
                        ? encryptedPath.Substring(0, encryptedPath.Length - 5)
                        : encryptedPath + ".decrypted";
                    tempPath = outputPath + ".tmp";
                    output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None);
                }

                try
                {
                    using (output)
                    using (var aes = new AesGcm(key, TagSize))
                    {
                        byte[] plaintext = new byte[chunkSize];
                        byte[] ciphertext = new byte[chunkSize];
                        byte[] tag = new byte[TagSize];

                        long processed = 0;
                        while (input.Position < input.Length)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            byte[] nonce = reader.ReadBytes(NonceSize);
                            if (nonce.Length != NonceSize)
                                throw new CryptographicException("File corrupted or truncated.");

                            int cipherLen = reader.ReadInt32();
                            if (cipherLen < 0 || cipherLen > chunkSize)
                                throw new CryptographicException("File corrupted or invalid chunk size.");

                            int read = reader.Read(ciphertext, 0, cipherLen);
                            if (read != cipherLen)
                                throw new CryptographicException("File corrupted or truncated.");

                            int tagRead = reader.Read(tag, 0, TagSize);
                            if (tagRead != TagSize)
                                throw new CryptographicException("File corrupted or truncated.");

                            aes.Decrypt(
                                nonce,
                                ciphertext.AsSpan(0, cipherLen),
                                tag,
                                plaintext.AsSpan(0, cipherLen)
                            );

                            if (writeOutput)
                            {
                                output.Write(plaintext, 0, cipherLen);
                            }

                            processed += cipherLen;
                            progress?.Invoke(processed, originalLength);
                        }

                        if (processed != originalLength)
                            throw new CryptographicException("File corrupted or length mismatch.");
                    }
                }
                catch
                {
                    if (writeOutput && !string.IsNullOrEmpty(tempPath) && File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                    throw;
                }

                if (writeOutput)
                {
                    FileHelpers.AtomicMove(tempPath, outputPath);
                }
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                Array.Clear(salt, 0, salt.Length);
            }
        }

        static void DecryptV1(
            string encryptedPath,
            byte[] key,
            Action<long, long>? progress,
            bool writeOutput,
            System.Threading.CancellationToken cancellationToken)
        {
            long fileLen = new FileInfo(encryptedPath).Length;
            if (fileLen < 28)
                throw new CryptographicException("File corrupted or too short.");

            if (fileLen > int.MaxValue)
                throw new NotSupportedException("File too large for single-pass GCM decryption.");

            byte[] fileBytes = FileHelpers.ReadAllBytesWithProgress(encryptedPath, progress, cancellationToken);

            ReadOnlySpan<byte> fileSpan = fileBytes.AsSpan();
            ReadOnlySpan<byte> nonce = fileSpan.Slice(0, NonceSize);
            ReadOnlySpan<byte> tag = fileSpan.Slice(fileBytes.Length - TagSize, TagSize);
            ReadOnlySpan<byte> ciphertext = fileSpan.Slice(NonceSize, fileBytes.Length - (NonceSize + TagSize));

            byte[] plaintext = new byte[ciphertext.Length];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            if (writeOutput)
            {
                string outputPath = encryptedPath.EndsWith(".nice")
                    ? encryptedPath.Substring(0, encryptedPath.Length - 5)
                    : encryptedPath + ".decrypted";
                FileHelpers.AtomicWrite(outputPath, plaintext);
            }

            Array.Clear(plaintext, 0, plaintext.Length);
        }

        static byte[] DeriveKey(char[] password, byte[] salt, int iterations)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                using (var kdf = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256))
                {
                    return kdf.GetBytes(KeySize);
                }
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }
    }
}
