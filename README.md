# NiceCrypt v1.2

NiceCrypt is a high-performance, cross-platform terminal utility designed for secure file orchestration. It implements **AES-256-GCM** (Galois/Counter Mode) to ensure both data confidentiality and authenticity through a modern, interactive command-line interface.

## 🚀 Key Features

* **Authenticated Encryption:** Uses AES-256-GCM to provide built-in integrity checking, preventing unauthorized data tampering.
* **Interactive Shell:** A dedicated CLI environment with tab-based autocomplete, command history, and a breadcrumb-style prompt.
* **Hybrid Key Logic:** Support for cryptographically strong **Key Files** or **Password-Based Key Derivation**.
* **In-Place Operations:** Rekey existing encrypted volumes without full manual decryption/re-encryption cycles.
* **Integrity Verification:** Specialized `verify` mode to validate file health and credentials without writing data to disk.
* **OS Agnostic:** Built on .NET, making it fully compatible with Linux, macOS, and Windows.

## 📂 Architecture

The project follows a modular design for high maintainability:

``` text
├── Crypto/          # Core logic (AES-256-GCM implementation)
│   ├── Encryptor.cs # Encryption streams and GCM tag generation
│   ├── Decryptor.cs # Authentication and bit-stream restoration
│   └── Rekey.cs     # Key rotation logic
├── Models/          # Data structures for key storage and headers
├── Utils/           # Secure random generation and IO helpers
└── Program.cs       # Interactive shell and command routing
``` 

## 🛠 Installation & Quick Start

**Prerequisites:** .NET 6.0 SDK or higher.

``` bash
# Clone the repository
git clone https://github.com/username/nicecrypt.git
cd nicecrypt

# Build and execute the shell
dotnet run
``` 

## 💻 Command Reference

### Encryption & Security
| Command | Description |
|:---|:---|
| `encrypt <file> [key]` | Encrypts target. Generates a `.key` file if one isn't specified. |
| `encrypt <file> -p` | Password-protected mode (Prompts for secure input). |
| `decrypt <file> <key>` | Decrypts using the specified key file. |
| `verify <file> -p` | Validates password/integrity without outputting a file. |
| `rekey <file> <old> <new>` | Rotates keys for an existing `.nice` file. |

### System & Navigation
| Command | Description |
|:---|:---|
| `ls` / `cd` | Navigate the local filesystem within the NiceCrypt shell. |
| `info <file>` | Inspect file headers, encryption mode, and versioning. |
| `keygen <path>` | Generate a standalone high-entropy master key. |

## 🛡 Security Specifications

* **Algorithm:** AES (Advanced Encryption Standard)
* **Key Length:** 256-bit
* **Mode:** GCM (Galois/Counter Mode)
* **Entropy:** Hardware-seeded secure random number generation (`SecureRandom.cs`).
* **File Format:** Proprietary `.nice` binary format containing Nonce, Auth Tag, and Encrypted Payload.

## ⚖ License
Distributed under the MIT License. See `LICENSE` for more information.
