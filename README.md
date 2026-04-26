# NiceCrypt v1.2

A secure CLI file encryption utility built with .NET, utilizing AES-256-GCM for high-performance and authenticated encryption.

## Features

* **AES-256-GCM Encryption:** Uses Galois/Counter Mode for both confidentiality and data integrity.
* **Flexible Key Management:** Support for randomly generated key files or password-based encryption.
* **Interactive Shell:** Built-in shell environment with tab autocomplete and directory navigation.
* **Rekeying:** Change encryption keys or passwords without full manual decryption/re-encryption cycles.
* **Verification:** Verify if a file can be successfully decrypted without writing output to disk.

## Project Structure

```text
.
├── Crypto
│   ├── Decryptor.cs
│   ├── Encryptor.cs
│   └── Rekey.cs
├── Models
│   └── KeyFile.cs
├── Utils
│   ├── FileHelpers.cs
│   └── SecureRandom.cs
├── Program.cs
├── nicecrypt.csproj
└── nicecrypt.sln
```

## Usage

Run the application using the .NET CLI:

```bash
dotnet run
```

### Available Commands

| Command | Description |
| --- | --- |
| `encrypt <file> [key]` | Encrypt file (generates key if omitted) |
| `encrypt <file> -p` | Encrypt with password |
| `decrypt <file> <key>` | Decrypt file |
| `decrypt <file> -p` | Decrypt with password |
| `verify <file> <key>` | Verify decryptability without output |
| `keygen <keyfile>` | Generate a key file |
| `rekey <file> <old> <new>` | Re-encrypt with new key |
| `info [file]` | Show tool or file info |
| `ls` | List directory |
| `cd <path>` | Change directory |

## Technical Details

* **Algorithm:** AES-256-GCM
* **File Extension:** `.nice`
* **Framework:** .NET

## License

This project is licensed under the MIT License.
