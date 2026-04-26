using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NiceCrypt.Models;
using NiceCrypt.Utils;

namespace NiceCrypt.Crypto
{
    public static class Rekey
    {
        const string Magic = "NICE";
        const byte Version2 = 2;
        const byte Version3 = 3;
        const int NonceSize = 12;
        const int TagSize = 16;
        const int DefaultChunkSize = 4 * 1024 * 1024;
        const int Pbkdf2Iterations = 200000;

        public static void Execute(
            string inputNice,
            string oldKeyFile,
            string newKeyFile,
            string outputNice,
            Action<long, long>? progress,
            System.Threading.CancellationToken cancellationToken)
        {
            byte[] oldKey = LoadKey(oldKeyFile);
            byte[] newKey = LoadOrCreateKey(newKeyFile);

            try
            {
                using (var input = new FileStream(inputNice, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true))
                {
                    byte[] magicBytes = reader.ReadBytes(4);
                    string magic = Encoding.ASCII.GetString(magicBytes);
                    if (magic != Magic)
                        throw new CryptographicException("Unsupported input format for rekey.");

                    byte version = reader.ReadByte();
                    if (version == Version2)
                    {
                        RekeyV2(reader, input, oldKey, newKey, outputNice, progress, cancellationToken);
                    }
                    else if (version == Version3)
                    {
                        throw new CryptographicException("Password-based files require password rekey.");
                    }
                    else
                    {
                        throw new CryptographicException("Unsupported .nice format version.");
                    }
                }
            }
            finally
            {
                Array.Clear(oldKey, 0, oldKey.Length);
                Array.Clear(newKey, 0, newKey.Length);
            }
        }

        public static void ExecuteWithPassword(
            string inputNice,
            char[] oldPassword,
            char[] newPassword,
            string outputNice,
            Action<long, long>? progress,
            System.Threading.CancellationToken cancellationToken)
        {
            using (var input = new FileStream(inputNice, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true))
            {
                byte[] magicBytes = reader.ReadBytes(4);
                string magic = Encoding.ASCII.GetString(magicBytes);
                if (magic != Magic)
                    throw new CryptographicException("Unsupported input format for rekey.");

                byte version = reader.ReadByte();
                if (version != Version3)
                    throw new CryptographicException("Password rekey only supports v3 files.");

                RekeyV3(reader, input, oldPassword, newPassword, outputNice, progress, cancellationToken);
            }
        }

        static byte[] LoadKey(string keyFilePath)
        {
            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException("Key file not found.", keyFilePath);

            string json = File.ReadAllText(keyFilePath);
            var keyData = JsonSerializer.Deserialize<KeyFile>(json);

            if (keyData == null || keyData.Algorithm != "AES-256-GCM")
                throw new CryptographicException("Invalid or unsupported key file.");

            return Convert.FromBase64String(keyData.Key);
        }

        static byte[] LoadOrCreateKey(string keyFilePath)
        {
            if (File.Exists(keyFilePath))
            {
                return LoadKey(keyFilePath);
            }

            byte[] key = SecureRandom.GenerateBytes(32);
            var keyData = new KeyFile
            {
                Algorithm = "AES-256-GCM",
                Key = Convert.ToBase64String(key),
                Created = DateTime.UtcNow
            };

            string json = JsonSerializer.Serialize(keyData, new JsonSerializerOptions { WriteIndented = true });
            FileHelpers.AtomicWrite(keyFilePath, Encoding.UTF8.GetBytes(json));
            return key;
        }

        static void RekeyV2(
            BinaryReader reader,
            FileStream input,
            byte[] oldKey,
            byte[] newKey,
            string outputNice,
            Action<long, long>? progress,
            System.Threading.CancellationToken cancellationToken)
        {
            int chunkSize = reader.ReadInt32();
            long originalLength = reader.ReadInt64();

            string tempPath = outputNice + ".tmp";
            try
            {
                using (var output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true))
                using (var aesOld = new AesGcm(oldKey, TagSize))
                using (var aesNew = new AesGcm(newKey, TagSize))
                {
                    writer.Write(Encoding.ASCII.GetBytes(Magic));
                    writer.Write(Version2);
                    writer.Write(DefaultChunkSize);
                    writer.Write(originalLength);

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

                        aesOld.Decrypt(
                            nonce,
                            ciphertext.AsSpan(0, cipherLen),
                            tag,
                            plaintext.AsSpan(0, cipherLen)
                        );

                        byte[] newNonce = SecureRandom.GenerateBytes(NonceSize);
                        aesNew.Encrypt(
                            newNonce,
                            plaintext.AsSpan(0, cipherLen),
                            ciphertext.AsSpan(0, cipherLen),
                            tag
                        );

                        writer.Write(newNonce);
                        writer.Write(cipherLen);
                        writer.Write(ciphertext, 0, cipherLen);
                        writer.Write(tag, 0, tag.Length);

                        processed += cipherLen;
                        progress?.Invoke(processed, originalLength);
                    }
                }
            }
            catch
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
                throw;
            }

            FileHelpers.AtomicMove(tempPath, outputNice);
        }

        static void RekeyV3(
            BinaryReader reader,
            FileStream input,
            char[] oldPassword,
            char[] newPassword,
            string outputNice,
            Action<long, long>? progress,
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

            byte[] oldKey = DeriveKey(oldPassword, salt, iterations);
            byte[] newSalt = SecureRandom.GenerateBytes(16);
            byte[] newKey = DeriveKey(newPassword, newSalt, Pbkdf2Iterations);

            string tempPath = outputNice + ".tmp";
            try
            {
                using (var output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true))
                using (var aesOld = new AesGcm(oldKey, TagSize))
                using (var aesNew = new AesGcm(newKey, TagSize))
                {
                    writer.Write(Encoding.ASCII.GetBytes(Magic));
                    writer.Write(Version3);
                    writer.Write(DefaultChunkSize);
                    writer.Write(originalLength);
                    writer.Write((byte)1); // PBKDF2-SHA256
                    writer.Write(Pbkdf2Iterations);
                    writer.Write((byte)newSalt.Length);
                    writer.Write(newSalt);

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

                        aesOld.Decrypt(
                            nonce,
                            ciphertext.AsSpan(0, cipherLen),
                            tag,
                            plaintext.AsSpan(0, cipherLen)
                        );

                        byte[] newNonce = SecureRandom.GenerateBytes(NonceSize);
                        aesNew.Encrypt(
                            newNonce,
                            plaintext.AsSpan(0, cipherLen),
                            ciphertext.AsSpan(0, cipherLen),
                            tag
                        );

                        writer.Write(newNonce);
                        writer.Write(cipherLen);
                        writer.Write(ciphertext, 0, cipherLen);
                        writer.Write(tag, 0, tag.Length);

                        processed += cipherLen;
                        progress?.Invoke(processed, originalLength);
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
                Array.Clear(oldKey, 0, oldKey.Length);
                Array.Clear(newKey, 0, newKey.Length);
                Array.Clear(salt, 0, salt.Length);
                Array.Clear(newSalt, 0, newSalt.Length);
            }

            FileHelpers.AtomicMove(tempPath, outputNice);
        }

        static byte[] DeriveKey(char[] password, byte[] salt, int iterations)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                using (var kdf = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256))
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
