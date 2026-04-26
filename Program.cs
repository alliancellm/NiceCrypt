using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using NiceCrypt.Crypto;
using NiceCrypt.Models;
using NiceCrypt.Utils;

namespace NiceCrypt
{
    class Program
    {
        const string AppName = "NiceCrypt";
        const string AppVersion = "1.2";
        const string Magic = "NICE";
        const byte Version2 = 2;
        const byte Version3 = 3;

        static readonly string[] BuiltinCommands = new[]
        {
            "encrypt", "decrypt", "verify", "keygen", "rekey",
            "version", "info",
            "ls", "dir", "cd", "cls", "clear", "help", "exit", "quit"
        };

        static HashSet<string>? systemCommandsCache;

        static void Main(string[] args)
        {
            Console.Title = $"{AppName} CLI";
            RenderHeader();

            var history = new List<string>();

            while (true)
            {
                int lineStart = Console.CursorTop;
                string input = ReadLineWithHistory(history, lineStart);
                if (string.IsNullOrWhiteSpace(input)) continue;

                // Parse arguments handling quotes: encrypt "my file.pdf"
                var commandArgs = ParseArguments(input);
                string command = commandArgs[0].ToLowerInvariant();
                string[] cmdParams = commandArgs.Skip(1).ToArray();

                try
                {
                    switch (command)
                    {
                        case "encrypt":
                            HandleEncrypt(cmdParams);
                            break;
                        case "decrypt":
                            HandleDecrypt(cmdParams);
                            break;
                        case "verify":
                            HandleVerify(cmdParams);
                            break;
                        case "keygen":
                            HandleKeygen(cmdParams);
                            break;
                        case "rekey":
                            HandleRekey(cmdParams);
                            break;
                        case "version":
                            HandleVersion();
                            break;
                        case "info":
                            HandleInfo(cmdParams);
                            break;
                        case "ls":
                        case "dir":
                            HandleLs();
                            break;
                        case "cd":
                            HandleCd(cmdParams);
                            break;
                        case "cls":
                        case "clear":
                            Console.Clear();
                            break;
                        case "help":
                            ShowHelp();
                            break;
                        case "exit":
                        case "quit":
                            return;
                        default:
                            if (!RunSystemCommand(input))
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"Unknown command: {command}");
                                Console.ResetColor();
                            }
                            break;
                    }
                }
                catch (OperationCanceledException)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Operation canceled.");
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    try
                    {
                        ThrowFriendly(ex);
                    }
                    catch (Exception friendly)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Error: {friendly.Message}");
                        Console.ResetColor();
                    }
                }
                Console.WriteLine();
            }
        }

        static void HandleEncrypt(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: encrypt <file> [keyfile] [-d]");
                return;
            }

            bool deleteAfter = HasFlag(args, "-d");
            bool usePassword = HasFlag(args, "-p");
            bool force = HasFlag(args, "-f");
            var filtered = args.Where(a =>
                !a.Equals("-d", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("-p", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("-f", StringComparison.OrdinalIgnoreCase)).ToArray();

            if (filtered.Length < 1)
            {
                Console.WriteLine("Usage: encrypt <file> [keyfile] [-d]");
                return;
            }

            string inputFile = ResolvePath(filtered[0]);
            string? keyFile = filtered.Length > 1 ? ResolvePath(filtered[1]) : null;
            if (usePassword && filtered.Length > 1)
            {
                Console.WriteLine("Usage: encrypt <file> [-p] [-d]");
                return;
            }
            string outputFile = inputFile + ".nice";
            string keyFileDisplay = string.IsNullOrEmpty(keyFile) ? inputFile + ".key" : keyFile;

            if (!force && File.Exists(outputFile))
            {
                if (!ConfirmOverwrite(outputFile, "Encrypted output"))
                    return;
            }

            if (string.IsNullOrEmpty(keyFile) && !usePassword)
            {
                string defaultKeyFile = inputFile + ".key";
                if (!force && File.Exists(defaultKeyFile))
                {
                    if (!ConfirmOverwrite(defaultKeyFile, "Key file"))
                        return;
                }
            }

            long totalBytes = new FileInfo(inputFile).Length;
            RenderOperationPanel(
                "ENCRYPT",
                inputFile,
                outputFile,
                usePassword ? "Password (PBKDF2-SHA256)" : keyFileDisplay,
                totalBytes);

            char[]? passwordToUse = null;
            if (usePassword)
            {
                char[] password = PromptPassword("Password");
                char[] confirm = PromptPassword("Confirm");
                if (!password.SequenceEqual(confirm))
                {
                    Array.Clear(password, 0, password.Length);
                    Array.Clear(confirm, 0, confirm.Length);
                    throw new InvalidOperationException("Passwords do not match.");
                }
                Array.Clear(confirm, 0, confirm.Length);
                passwordToUse = password;
            }

            RunWithProgress("Encrypting", totalBytes, (progress, token) => 
            {
                if (usePassword)
                {
                    Encryptor.ExecuteWithPassword(inputFile, passwordToUse ?? Array.Empty<char>(), progress, token);
                }
                else
                {
                    Encryptor.Execute(inputFile, keyFile, progress, token);
                }
            });
            if (!usePassword && !string.IsNullOrEmpty(keyFileDisplay))
            {
                string keyPath = string.IsNullOrEmpty(keyFile) ? inputFile + ".key" : keyFile;
                if (File.Exists(keyPath)) FileHelpers.TryRestrictFilePermissions(keyPath);
            }
            if (passwordToUse != null) Array.Clear(passwordToUse, 0, passwordToUse.Length);
            
            if (deleteAfter)
            {
                File.Delete(inputFile);
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n[SUCCESS] Encrypted: {Path.GetFileName(inputFile)}.nice");
            Console.ResetColor();
        }

        static void HandleDecrypt(string[] args)
        {
            bool usePassword = HasFlag(args, "-p");
            bool force = HasFlag(args, "-f");
            var filtered = args.Where(a =>
                !a.Equals("-p", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("-f", StringComparison.OrdinalIgnoreCase)).ToArray();

            if (filtered.Length < 1)
            {
                Console.WriteLine("Usage: decrypt <nice_file> <keyfile>");
                Console.WriteLine("   or: decrypt <nice_file> -p");
                return;
            }

            string encFile = ResolvePath(filtered[0]);
            string keyFile = filtered.Length > 1 ? ResolvePath(filtered[1]) : string.Empty;
            NiceFileMode mode = DetectNiceMode(encFile);

            if (mode == NiceFileMode.PasswordV3)
            {
                usePassword = true;
            }

            if (!usePassword)
            {
                if (string.IsNullOrEmpty(keyFile))
                {
                    keyFile = FindDefaultKeyFile(encFile);
                }

                if (string.IsNullOrEmpty(keyFile))
                {
                    Console.WriteLine("Key file required for this file.");
                    return;
                }
            }

            string outputFile = encFile.EndsWith(".nice")
                ? encFile.Substring(0, encFile.Length - 5)
                : encFile + ".decrypted";

            if (!force && File.Exists(outputFile))
            {
                if (!ConfirmOverwrite(outputFile, "Decrypted output"))
                    return;
            }

            long totalBytes = new FileInfo(encFile).Length;
            RenderOperationPanel(
                "DECRYPT",
                encFile,
                outputFile,
                usePassword ? "Password (PBKDF2-SHA256)" : keyFile,
                totalBytes);

            char[]? passwordToUse = null;
            if (usePassword)
            {
                passwordToUse = PromptPassword("Password");
            }

            RunWithProgress("Decrypting", 0, (progress, token) =>
            {
                if (usePassword)
                {
                    Decryptor.ExecuteWithPassword(encFile, passwordToUse ?? Array.Empty<char>(), progress, token);
                }
                else
                {
                    Decryptor.Execute(encFile, keyFile, progress, token);
                }
            });
            if (passwordToUse != null) Array.Clear(passwordToUse, 0, passwordToUse.Length);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n[SUCCESS] Decrypted: {Path.GetFileName(encFile).Replace(".nice", "")}");
            Console.ResetColor();
        }

        static void HandleVerify(string[] args)
        {
            bool usePassword = HasFlag(args, "-p");
            var filtered = args.Where(a => !a.Equals("-p", StringComparison.OrdinalIgnoreCase)).ToArray();

            if (filtered.Length < 1)
            {
                Console.WriteLine("Usage: verify <nice_file> <keyfile>");
                Console.WriteLine("   or: verify <nice_file> -p");
                return;
            }

            string encFile = ResolvePath(filtered[0]);
            string keyFile = filtered.Length > 1 ? ResolvePath(filtered[1]) : string.Empty;
            NiceFileMode mode = DetectNiceMode(encFile);

            if (mode == NiceFileMode.PasswordV3)
            {
                usePassword = true;
            }

            if (!usePassword)
            {
                if (string.IsNullOrEmpty(keyFile))
                {
                    keyFile = FindDefaultKeyFile(encFile);
                }

                if (string.IsNullOrEmpty(keyFile))
                {
                    Console.WriteLine("Key file required for this file.");
                    return;
                }
            }

            RunWithProgress("Verifying", () =>
            {
                if (usePassword)
                {
                    char[] password = PromptPassword("Password");
                    try
                    {
                        Decryptor.VerifyWithPassword(encFile, password);
                    }
                    finally
                    {
                        Array.Clear(password, 0, password.Length);
                    }
                }
                else
                {
                    Decryptor.Verify(encFile, keyFile);
                }
            });

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[SUCCESS] Verification passed.");
            Console.ResetColor();
        }

        static void HandleKeygen(string[] args)
        {
            bool force = HasFlag(args, "-f");
            var filtered = args.Where(a => !a.Equals("-f", StringComparison.OrdinalIgnoreCase)).ToArray();

            if (filtered.Length < 1)
            {
                Console.WriteLine("Usage: keygen <keyfile> [-f]");
                return;
            }

            string keyFilePath = ResolvePath(filtered[0]);

            if (!force && File.Exists(keyFilePath))
            {
                if (!ConfirmOverwrite(keyFilePath, "Key file"))
                    return;
            }

            byte[] key = SecureRandom.GenerateBytes(32);

            var keyData = new KeyFile
            {
                Algorithm = "AES-256-GCM",
                Key = Convert.ToBase64String(key),
                Created = DateTime.UtcNow
            };

            string json = System.Text.Json.JsonSerializer.Serialize(
                keyData,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }
            );

            FileHelpers.AtomicWrite(keyFilePath, System.Text.Encoding.UTF8.GetBytes(json));
            FileHelpers.TryRestrictFilePermissions(keyFilePath);

            Array.Clear(key, 0, key.Length);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[SUCCESS] Key file created: {Path.GetFileName(keyFilePath)}");
            Console.ResetColor();
        }

        static void HandleRekey(string[] args)
        {
            bool usePassword = HasFlag(args, "-p");
            bool force = HasFlag(args, "-f");
            var filtered = args.Where(a =>
                !a.Equals("-p", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("-f", StringComparison.OrdinalIgnoreCase)).ToArray();

            if (usePassword)
            {
                if (filtered.Length < 1)
                {
                    Console.WriteLine("Usage: rekey <nice_file> -p");
                    return;
                }

                string inputFilePwd = ResolvePath(filtered[0]);
                string outputFilePwd = inputFilePwd + ".rekey.nice";

                if (!force && File.Exists(outputFilePwd))
                {
                    if (!ConfirmOverwrite(outputFilePwd, "Rekey output"))
                        return;
                }

                RenderOperationPanel(
                    "REKEY",
                    inputFilePwd,
                    outputFilePwd,
                    "Password -> Password",
                    new FileInfo(inputFilePwd).Length);

                char[] oldPassword = PromptPassword("Old password");
                char[] newPassword = PromptPassword("New password");
                char[] confirm = PromptPassword("Confirm new");
                if (!newPassword.SequenceEqual(confirm))
                {
                    Array.Clear(oldPassword, 0, oldPassword.Length);
                    Array.Clear(newPassword, 0, newPassword.Length);
                    Array.Clear(confirm, 0, confirm.Length);
                    throw new InvalidOperationException("Passwords do not match.");
                }
                Array.Clear(confirm, 0, confirm.Length);

                RunWithProgressTwoPhase("Rekeying", 0, (progress, token) =>
                {
                    Rekey.ExecuteWithPassword(inputFilePwd, oldPassword, newPassword, outputFilePwd, progress, token);
                });
                Array.Clear(oldPassword, 0, oldPassword.Length);
                Array.Clear(newPassword, 0, newPassword.Length);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[SUCCESS] Rekeyed: {Path.GetFileName(outputFilePwd)}");
                Console.ResetColor();
                return;
            }

            if (filtered.Length < 3)
            {
                Console.WriteLine("Usage: rekey <nice_file> <old_keyfile> <new_keyfile>");
                return;
            }

            string inputFile = ResolvePath(filtered[0]);
            string oldKeyFile = ResolvePath(filtered[1]);
            string newKeyFile = ResolvePath(filtered[2]);
            string outputFile = inputFile + ".rekey.nice";

            if (!force && File.Exists(outputFile))
            {
                if (!ConfirmOverwrite(outputFile, "Rekey output"))
                    return;
            }

            RenderOperationPanel(
                "REKEY",
                inputFile,
                outputFile,
                $"Old: {oldKeyFile} | New: {newKeyFile}",
                new FileInfo(inputFile).Length);

            RunWithProgressTwoPhase("Rekeying", 0, (progress, token) =>
            {
                Rekey.Execute(inputFile, oldKeyFile, newKeyFile, outputFile, progress, token);
            });

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n[SUCCESS] Rekeyed: {Path.GetFileName(outputFile)}");
            Console.ResetColor();
        }

        static void HandleVersion()
        {
            Console.WriteLine($"{AppName} v{AppVersion}");
        }

        static void HandleInfo(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine($"{AppName} CLI");
                Console.WriteLine("Algorithm: AES-256-GCM");
                Console.WriteLine("Encrypted extension: .nice");
                Console.WriteLine("Encrypted format: v2/v3 chunked (.nice header + chunks)");
                Console.WriteLine("Password mode: PBKDF2-SHA256");
                Console.WriteLine("Legacy format: [nonce 12][ciphertext N][tag 16]");
                Console.WriteLine("Key file format: JSON (algorithm, key, created)");
                return;
            }

            string file = ResolvePath(args[0]);
            if (!File.Exists(file))
            {
                Console.WriteLine("File not found.");
                return;
            }

            FileInfo info = new FileInfo(file);
            Console.WriteLine($"File: {info.Name}");
            Console.WriteLine($"Size: {FileHelpers.BytesToString(info.Length)}");

            NiceFileMode mode = DetectNiceMode(file);
            switch (mode)
            {
                case NiceFileMode.PasswordV3:
                    Console.WriteLine("Format: v3 (.nice, password)");
                    ReadNiceHeaderV3(file);
                    break;
                case NiceFileMode.KeyV2:
                    Console.WriteLine("Format: v2 (.nice, keyfile)");
                    ReadNiceHeaderV2(file);
                    break;
                case NiceFileMode.LegacyV1:
                    Console.WriteLine("Format: v1 (legacy)");
                    break;
                default:
                    Console.WriteLine("Format: unknown");
                    break;
            }
        }

        static void HandleLs()
        {
            var path = Directory.GetCurrentDirectory();
            var dirs = Directory.GetDirectories(path);
            var files = Directory.GetFiles(path);

            Console.WriteLine($"Directory: {path}\n");

            foreach (var d in dirs)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"  [DIR]  {Path.GetFileName(d)}");
            }
            Console.ResetColor();

            foreach (var f in files)
            {
                var fi = new FileInfo(f);
                string size = FileHelpers.BytesToString(fi.Length);
                string name = Path.GetFileName(f);
                if (name.EndsWith(".nice", StringComparison.OrdinalIgnoreCase))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"  {size.PadLeft(10)}  ");
                    Console.Write(name);
                    Console.ResetColor();
                    Console.WriteLine("  [NICE]");
                }
                else
                {
                    Console.WriteLine($"  {size.PadLeft(10)}  {name}");
                }
            }
        }

        static void HandleCd(string[] args)
        {
            if (args.Length == 0) return;
            string newPath = Path.Combine(Directory.GetCurrentDirectory(), args[0]);
            string resolved = Path.GetFullPath(newPath);

            if (Directory.Exists(resolved))
            {
                Directory.SetCurrentDirectory(resolved);
            }
            else
            {
                throw new DirectoryNotFoundException($"Directory not found: {args[0]}");
            }
        }

        static void RunWithProgress(string operation, Action action)
        {
            var tokenSource = new CancellationTokenSource();
            var task = Task.Run(action, tokenSource.Token);
            
            Console.CursorVisible = false;
            Console.Write($"{operation} ");
            
            int spinnerCounter = 0;
            char[] spinner = { '|', '/', '-', '\\' };

            while (!task.IsCompleted)
            {
                Console.Write(spinner[spinnerCounter % 4]);
                Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                spinnerCounter++;
                Thread.Sleep(100);
            }
            
            Console.Write("Done.");
            Console.CursorVisible = true;

            if (task.IsFaulted)
            {
                throw task.Exception?.InnerException ?? new Exception("Operation failed");
            }
        }

        static void RunWithProgress(
            string operation,
            long totalBytes,
            Action<Action<long, long>, CancellationToken> action)
        {
            long processed = 0;
            long total = totalBytes;

            Action<long, long> progress = (done, totalFromSource) =>
            {
                Interlocked.Exchange(ref processed, done);
                if (total == 0 && totalFromSource > 0)
                {
                    total = totalFromSource;
                }
            };

            var tokenSource = new CancellationTokenSource();
            var stopwatch = Stopwatch.StartNew();
            var task = Task.Run(() => action(progress, tokenSource.Token), tokenSource.Token);

            Console.CursorVisible = false;
            int lastLength = 0;

            while (!task.IsCompleted)
            {
                if (Console.KeyAvailable)
                {
                    var key = Console.ReadKey(intercept: true);
                    if (key.Key == ConsoleKey.C || key.Key == ConsoleKey.Q || key.Key == ConsoleKey.Escape)
                    {
                        tokenSource.Cancel();
                    }
                }

                long done = Interlocked.Read(ref processed);
                string line = FormatProgressLine(operation, done, total, stopwatch.Elapsed);
                Console.Write("\r" + line);
                int padding = Math.Max(0, lastLength - line.Length);
                if (padding > 0) Console.Write(new string(' ', padding));
                lastLength = line.Length;
                Thread.Sleep(100);
            }

            if (task.IsCanceled)
            {
                Console.CursorVisible = true;
                throw new OperationCanceledException();
            }

            if (task.IsFaulted)
            {
                Console.CursorVisible = true;
                throw task.Exception?.InnerException ?? new Exception("Operation failed");
            }

            string finalLine = FormatProgressLine(operation, total, total, stopwatch.Elapsed) + " Done.";
            Console.Write("\r" + finalLine);
            int finalPadding = Math.Max(0, lastLength - finalLine.Length);
            if (finalPadding > 0) Console.Write(new string(' ', finalPadding));
            Console.CursorVisible = true;
        }

        static void RunWithProgressTwoPhase(
            string operation,
            long totalBytes,
            Action<Action<long, long>, CancellationToken> action)
        {
            long processed = 0;
            long total = totalBytes;

            Action<long, long> progress = (done, totalFromSource) =>
            {
                Interlocked.Exchange(ref processed, done);
                if (total == 0 && totalFromSource > 0)
                {
                    total = totalFromSource;
                }
            };

            var tokenSource = new CancellationTokenSource();
            var stopwatch = Stopwatch.StartNew();
            var task = Task.Run(() => action(progress, tokenSource.Token), tokenSource.Token);

            Console.CursorVisible = false;
            int lastLength = 0;

            while (!task.IsCompleted)
            {
                if (Console.KeyAvailable)
                {
                    var key = Console.ReadKey(intercept: true);
                    if (key.Key == ConsoleKey.C || key.Key == ConsoleKey.Q || key.Key == ConsoleKey.Escape)
                    {
                        tokenSource.Cancel();
                    }
                }

                long done = Interlocked.Read(ref processed);
                string line = FormatRekeyProgressLine(operation, done, total, stopwatch.Elapsed);
                Console.Write("\r" + line);
                int padding = Math.Max(0, lastLength - line.Length);
                if (padding > 0) Console.Write(new string(' ', padding));
                lastLength = line.Length;
                Thread.Sleep(100);
            }

            if (task.IsCanceled)
            {
                Console.CursorVisible = true;
                throw new OperationCanceledException();
            }

            if (task.IsFaulted)
            {
                Console.CursorVisible = true;
                throw task.Exception?.InnerException ?? new Exception("Operation failed");
            }

            string finalLine = FormatRekeyProgressLine(operation, total, total, stopwatch.Elapsed) + " Done.";
            Console.Write("\r" + finalLine);
            int finalPadding = Math.Max(0, lastLength - finalLine.Length);
            if (finalPadding > 0) Console.Write(new string(' ', finalPadding));
            Console.CursorVisible = true;
        }

        static string FormatProgressLine(string operation, long processed, long total, TimeSpan elapsed)
        {
            if (total <= 0) return $"{operation} ...";

            long safeProcessed = Math.Min(processed, total);
            double percent = total == 0 ? 0 : (double)safeProcessed / total;
            int barWidth = 24;
            int filled = (int)Math.Round(percent * barWidth);
            string bar = new string('#', Math.Max(0, filled)).PadRight(barWidth, '-');

            string doneText = FileHelpers.BytesToString(safeProcessed);
            string totalText = FileHelpers.BytesToString(total);
            int pct = (int)Math.Round(percent * 100);

            double seconds = Math.Max(0.1, elapsed.TotalSeconds);
            double mbPerSec = (safeProcessed / 1024d / 1024d) / seconds;
            string speedText = $"{mbPerSec:0.0} MB/s";

            return $"{operation} [{bar}] {pct,3}% ({doneText}/{totalText}) {speedText}  Press C to cancel";
        }

        static string FormatRekeyProgressLine(string operation, long processed, long total, TimeSpan elapsed)
        {
            if (total <= 0) return $"{operation} (phase 1/2) ...";

            long safeProcessed = Math.Min(processed, total);
            double percent = total == 0 ? 0 : (double)safeProcessed / total;
            int barWidth = 24;
            int filled = (int)Math.Round(percent * barWidth);
            string bar = new string('#', Math.Max(0, filled)).PadRight(barWidth, '-');

            string doneText = FileHelpers.BytesToString(safeProcessed);
            string totalText = FileHelpers.BytesToString(total);
            int pct = (int)Math.Round(percent * 100);

            double seconds = Math.Max(0.1, elapsed.TotalSeconds);
            double mbPerSec = (safeProcessed / 1024d / 1024d) / seconds;
            string speedText = $"{mbPerSec:0.0} MB/s";

            string phase = percent < 0.5 ? "Decrypting (phase 1/2)" : "Encrypting (phase 2/2)";
            return $"{operation} {phase} [{bar}] {pct,3}% ({doneText}/{totalText}) {speedText}  Press C to cancel";
        }

        static bool ConfirmOverwrite(string path, string label)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"{label} exists: {path}. Overwrite? [y/N] ");
            Console.ResetColor();

            string? answer = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(answer)) return false;
            return answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase);
        }

        static void ThrowFriendly(Exception ex)
        {
            if (ex is OperationCanceledException)
                throw ex;

            if (ex is FileNotFoundException fnf)
                throw new Exception($"Missing file: {fnf.FileName}");

            if (ex is CryptographicException)
                throw new Exception("Crypto error: wrong password/key or corrupted file.");

            throw ex;
        }

        static char[] PromptPassword(string label)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{label}: ");
            Console.ResetColor();

            var chars = new List<char>();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (chars.Count > 0)
                    {
                        chars.RemoveAt(chars.Count - 1);
                    }
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    chars.Add(key.KeyChar);
                }
            }

            return chars.ToArray();
        }

        static bool HasFlag(string[] args, string flag)
        {
            return args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        }

        static string FindDefaultKeyFile(string encFile)
        {
            string candidate1 = encFile + ".key";
            if (File.Exists(candidate1)) return candidate1;

            if (encFile.EndsWith(".nice", StringComparison.OrdinalIgnoreCase))
            {
                string withoutNice = encFile.Substring(0, encFile.Length - 5);
                string candidate2 = withoutNice + ".key";
                if (File.Exists(candidate2)) return candidate2;
            }

            return string.Empty;
        }

        enum NiceFileMode
        {
            Unknown,
            LegacyV1,
            KeyV2,
            PasswordV3
        }

        static NiceFileMode DetectNiceMode(string path)
        {
            if (!File.Exists(path)) return NiceFileMode.Unknown;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length < 5) return NiceFileMode.Unknown;
                    byte[] magicBytes = new byte[4];
                    int read = fs.Read(magicBytes, 0, 4);
                    if (read != 4) return NiceFileMode.Unknown;
                    string magic = System.Text.Encoding.ASCII.GetString(magicBytes);
                    if (magic != Magic) return NiceFileMode.LegacyV1;

                    int ver = fs.ReadByte();
                    if (ver == Version2) return NiceFileMode.KeyV2;
                    if (ver == Version3) return NiceFileMode.PasswordV3;
                    return NiceFileMode.Unknown;
                }
            }
            catch
            {
                return NiceFileMode.Unknown;
            }
        }

        static void ReadNiceHeaderV2(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var reader = new BinaryReader(fs, System.Text.Encoding.UTF8, leaveOpen: false))
                {
                    byte[] magicBytes = reader.ReadBytes(4);
                    string magic = System.Text.Encoding.ASCII.GetString(magicBytes);
                    if (magic != Magic) return;

                    byte version = reader.ReadByte();
                    if (version != Version2) return;

                    int chunkSize = reader.ReadInt32();
                    long originalLength = reader.ReadInt64();

                    Console.WriteLine($"Chunk size: {FileHelpers.BytesToString(chunkSize)}");
                    Console.WriteLine($"Original size: {FileHelpers.BytesToString(originalLength)}");
                }
            }
            catch
            {
                Console.WriteLine("Header: unreadable");
            }
        }

        static void ReadNiceHeaderV3(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var reader = new BinaryReader(fs, System.Text.Encoding.UTF8, leaveOpen: false))
                {
                    byte[] magicBytes = reader.ReadBytes(4);
                    string magic = System.Text.Encoding.ASCII.GetString(magicBytes);
                    if (magic != Magic) return;

                    byte version = reader.ReadByte();
                    if (version != Version3) return;

                    int chunkSize = reader.ReadInt32();
                    long originalLength = reader.ReadInt64();
                    byte kdfId = reader.ReadByte();
                    int iterations = reader.ReadInt32();
                    byte saltLen = reader.ReadByte();
                    byte[] salt = reader.ReadBytes(saltLen);

                    Console.WriteLine($"Chunk size: {FileHelpers.BytesToString(chunkSize)}");
                    Console.WriteLine($"Original size: {FileHelpers.BytesToString(originalLength)}");
                    Console.WriteLine($"KDF: {(kdfId == 1 ? "PBKDF2-SHA256" : "Unknown")}");
                    Console.WriteLine($"Iterations: {iterations}");
                    Console.WriteLine($"Salt: {Convert.ToHexString(salt)}");
                }
            }
            catch
            {
                Console.WriteLine("Header: unreadable");
            }
        }

        static bool RunSystemCommand(string commandLine)
        {
            try
            {
                ProcessStartInfo psi;

                if (OperatingSystem.IsWindows())
                {
                    psi = new ProcessStartInfo("cmd.exe", "/c " + commandLine);
                }
                else
                {
                    psi = new ProcessStartInfo("/bin/bash", "-c \"" + EscapeForBash(commandLine) + "\"");
                }

                psi.WorkingDirectory = Directory.GetCurrentDirectory();
                psi.UseShellExecute = false;

                using (var process = Process.Start(psi))
                {
                    if (process == null) return false;
                    process.WaitForExit();
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        static string EscapeForBash(string input)
        {
            return input.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        static string ResolvePath(string input)
        {
            return Path.IsPathRooted(input) 
                ? input 
                : Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), input));
        }

        static List<string> ParseArguments(string commandLine)
        {
            var matches = Regex.Matches(commandLine, @"[\""].+?[\""]|[^ ]+")
                .Select(m => m.Value.Trim('"'))
                .ToList();
            return matches;
        }

        static string GetShortPath()
        {
            string path = Directory.GetCurrentDirectory();
            string root = Path.GetPathRoot(path) ?? string.Empty;
            if (path == root) return path;
            return Path.GetFileName(path);
        }

        static string GetPromptPath()
        {
            string path = Directory.GetCurrentDirectory();
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            if (!string.IsNullOrEmpty(home) && path.StartsWith(home, StringComparison.Ordinal))
            {
                string relative = path.Substring(home.Length);
                if (string.IsNullOrEmpty(relative)) return "~";
                return "~" + relative.Replace('\\', '/');
            }

            return path.Replace('\\', '/');
        }

        static int RenderPrompt()
        {
            string user = Environment.UserName;
            string host = Environment.MachineName;
            string path = GetPromptPath();
            string promptPlain = $"NC {user}@{host} {path} > ";

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("NC");
            Console.ResetColor();

            Console.Write(" ");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{user}@{host}");
            Console.ResetColor();

            Console.Write(" ");

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.Write(path);
            Console.ResetColor();

            Console.Write(" > ");
            return promptPlain.Length;
        }

        static void RenderHeader()
        {
            int width = 70;
            string line = new string('-', width);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("+" + line + "+");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("| ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{AppName} v{AppVersion}");
            Console.ResetColor();
            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("AES-256-GCM");
            Console.ResetColor();
            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write(".nice");
            Console.ResetColor();
            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("Tab: autocomplete");
            Console.ResetColor();
            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("C: cancel");
            Console.ResetColor();

            int used = 2 + $"{AppName} v{AppVersion}".Length + 3 + "AES-256-GCM".Length + 3 + ".nice".Length + 3 + "Tab: autocomplete".Length + 3 + "C: cancel".Length;
            int padding = Math.Max(0, width - used);
            if (padding > 0) Console.Write(new string(' ', padding));
            Console.WriteLine(" |");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("+" + line + "+");
            Console.ResetColor();
            Console.WriteLine("Type 'help' for commands.");
            Console.WriteLine();
        }

        static void RenderOperationPanel(
            string title,
            string inputPath,
            string outputPath,
            string keyPath,
            long totalBytes)
        {
            string line = new string('-', 70);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("+" + line + "+");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("| ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{title} MODE");
            Console.ResetColor();
            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(FileHelpers.BytesToString(totalBytes));
            Console.ResetColor();
            Console.Write(" | ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Press C to cancel");
            Console.ResetColor();

            int used = 2 + $"{title} MODE".Length + 3 + FileHelpers.BytesToString(totalBytes).Length + 3 + "Press C to cancel".Length;
            int padding = Math.Max(0, 70 - used);
            if (padding > 0) Console.Write(new string(' ', padding));
            Console.WriteLine(" |");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("+" + line + "+");
            Console.ResetColor();

            PrintKeyValue("Input", inputPath, ConsoleColor.Blue);
            PrintKeyValue("Output", outputPath, ConsoleColor.Green);
            PrintKeyValue("Key", keyPath, ConsoleColor.Magenta);
            Console.WriteLine();
        }

        static void PrintKeyValue(string key, string value, ConsoleColor valueColor)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{key,-8}");
            Console.ResetColor();
            Console.Write(": ");
            Console.ForegroundColor = valueColor;
            Console.WriteLine(value);
            Console.ResetColor();
        }

        static string ReadLineWithHistory(List<string> history, int lineStart)
        {
            var buffer = new List<char>();
            int cursor = 0;
            int historyIndex = -1;
            int lastRenderLength = 0;

            RenderPrompt();

            while (true)
            {
                var key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    string line = new string(buffer.ToArray());
                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        history.Add(line);
                    }
                    return line;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (cursor > 0)
                    {
                        buffer.RemoveAt(cursor - 1);
                        cursor--;
                    }
                }
                else if (key.Key == ConsoleKey.Delete)
                {
                    if (cursor < buffer.Count)
                    {
                        buffer.RemoveAt(cursor);
                    }
                }
                else if (key.Key == ConsoleKey.LeftArrow)
                {
                    if (cursor > 0) cursor--;
                }
                else if (key.Key == ConsoleKey.RightArrow)
                {
                    if (cursor < buffer.Count) cursor++;
                }
                else if (key.Key == ConsoleKey.Home)
                {
                    cursor = 0;
                }
                else if (key.Key == ConsoleKey.End)
                {
                    cursor = buffer.Count;
                }
                else if (key.Key == ConsoleKey.UpArrow)
                {
                    if (history.Count > 0)
                    {
                        if (historyIndex == -1)
                            historyIndex = history.Count - 1;
                        else if (historyIndex > 0)
                            historyIndex--;

                        buffer = history[historyIndex].ToList();
                        cursor = buffer.Count;
                    }
                }
                else if (key.Key == ConsoleKey.DownArrow)
                {
                    if (history.Count > 0 && historyIndex != -1)
                    {
                        if (historyIndex < history.Count - 1)
                        {
                            historyIndex++;
                            buffer = history[historyIndex].ToList();
                        }
                        else
                        {
                            historyIndex = -1;
                            buffer = new List<char>();
                        }
                        cursor = buffer.Count;
                    }
                }
                else if (key.Key == ConsoleKey.Tab)
                {
                    bool updatedLineStart;
                    HandleTabCompletion(ref buffer, ref cursor, ref lineStart, out updatedLineStart);
                    if (updatedLineStart)
                    {
                        lastRenderLength = 0;
                    }
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    buffer.Insert(cursor, key.KeyChar);
                    cursor++;
                }

                Console.SetCursorPosition(0, lineStart);
                int promptLen = RenderPrompt();
                string current = new string(buffer.ToArray());
                Console.Write(current);

                int clearCount = Math.Max(0, lastRenderLength - current.Length);
                if (clearCount > 0)
                {
                    Console.Write(new string(' ', clearCount));
                }

                Console.SetCursorPosition(promptLen + cursor, lineStart);
                lastRenderLength = current.Length;
            }
        }

        static void HandleTabCompletion(
            ref List<char> buffer,
            ref int cursor,
            ref int lineStart,
            out bool updatedLineStart)
        {
            updatedLineStart = false;

            int tokenStart = FindTokenStart(buffer, cursor);
            string prefix = new string(buffer.Skip(tokenStart).Take(cursor - tokenStart).ToArray());

            bool isFirstToken = IsFirstToken(buffer, tokenStart);
            List<string> matches = isFirstToken
                ? GetCommandCompletions(prefix)
                : GetFileCompletions(prefix);

            if (matches.Count == 0)
            {
                return;
            }

            string insertText = matches[0];

            if (matches.Count > 1)
            {
                string common = LongestCommonPrefix(matches);
                if (!string.IsNullOrEmpty(common) && common.Length > prefix.Length)
                {
                    insertText = common;
                }
                else
                {
                    Console.WriteLine();
                    foreach (var m in matches)
                    {
                        Console.Write(m);
                        Console.Write("  ");
                    }
                    Console.WriteLine();
                    lineStart = Console.CursorTop;
                    updatedLineStart = true;
                }
            }

            ReplaceToken(ref buffer, ref cursor, tokenStart, prefix.Length, insertText);

            if (matches.Count == 1 && !insertText.EndsWith("/") && !insertText.EndsWith("\\"))
            {
                buffer.Insert(cursor, ' ');
                cursor++;
            }
        }

        static int FindTokenStart(List<char> buffer, int cursor)
        {
            int i = Math.Min(cursor - 1, buffer.Count - 1);
            while (i >= 0)
            {
                if (char.IsWhiteSpace(buffer[i])) return i + 1;
                i--;
            }
            return 0;
        }

        static bool IsFirstToken(List<char> buffer, int tokenStart)
        {
            for (int i = 0; i < tokenStart; i++)
            {
                if (!char.IsWhiteSpace(buffer[i])) return false;
            }
            return true;
        }

        static void ReplaceToken(
            ref List<char> buffer,
            ref int cursor,
            int tokenStart,
            int tokenLength,
            string replacement)
        {
            buffer.RemoveRange(tokenStart, tokenLength);
            buffer.InsertRange(tokenStart, replacement);
            cursor = tokenStart + replacement.Length;
        }

        static List<string> GetCommandCompletions(string prefix)
        {
            var matches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var cmd in BuiltinCommands)
            {
                if (cmd.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(cmd);
                }
            }

            foreach (var cmd in GetSystemCommands())
            {
                if (cmd.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(cmd);
                }
            }

            return matches.OrderBy(m => m, StringComparer.OrdinalIgnoreCase).ToList();
        }

        static IEnumerable<string> GetSystemCommands()
        {
            if (systemCommandsCache != null) return systemCommandsCache;

            systemCommandsCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrWhiteSpace(pathEnv)) return systemCommandsCache;

            var pathSeparators = new[] { Path.PathSeparator };
            var dirs = pathEnv.Split(pathSeparators, StringSplitOptions.RemoveEmptyEntries);

            var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (OperatingSystem.IsWindows())
            {
                string? pathext = Environment.GetEnvironmentVariable("PATHEXT");
                if (!string.IsNullOrWhiteSpace(pathext))
                {
                    foreach (var ext in pathext.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        exts.Add(ext);
                    }
                }
            }

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        string name = Path.GetFileName(file);
                        string ext = Path.GetExtension(name);

                        if (OperatingSystem.IsWindows())
                        {
                            if (exts.Count == 0 || exts.Contains(ext))
                            {
                                systemCommandsCache.Add(Path.GetFileNameWithoutExtension(name));
                            }
                        }
                        else
                        {
                            systemCommandsCache.Add(name);
                        }
                    }
                }
                catch
                {
                    // Ignore unreadable PATH entries
                }
            }

            return systemCommandsCache;
        }

        static List<string> GetFileCompletions(string prefix)
        {
            string cwd = Directory.GetCurrentDirectory();
            string normalized = prefix.Replace('\\', '/');

            string dirPart;
            string filePart;

            int lastSlash = normalized.LastIndexOf('/');
            if (lastSlash >= 0)
            {
                dirPart = normalized.Substring(0, lastSlash + 1);
                filePart = normalized.Substring(lastSlash + 1);
            }
            else
            {
                dirPart = string.Empty;
                filePart = normalized;
            }

            string baseDir = string.IsNullOrEmpty(dirPart)
                ? cwd
                : ResolvePath(dirPart);

            if (!Directory.Exists(baseDir)) return new List<string>();

            var matches = new List<string>();

            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(baseDir))
                {
                    string name = Path.GetFileName(entry);
                    if (!name.StartsWith(filePart, StringComparison.OrdinalIgnoreCase)) continue;

                    bool isDir = Directory.Exists(entry);
                    string suffix = isDir ? "/" : string.Empty;
                    matches.Add(dirPart + name + suffix);
                }
            }
            catch
            {
                return new List<string>();
            }

            matches.Sort(StringComparer.OrdinalIgnoreCase);
            return matches;
        }

        static string LongestCommonPrefix(List<string> items)
        {
            if (items.Count == 0) return string.Empty;
            string prefix = items[0];
            for (int i = 1; i < items.Count; i++)
            {
                prefix = CommonPrefix(prefix, items[i]);
                if (prefix.Length == 0) break;
            }
            return prefix;
        }

        static string CommonPrefix(string a, string b)
        {
            int len = Math.Min(a.Length, b.Length);
            int i = 0;
            while (i < len && a[i] == b[i]) i++;
            return a.Substring(0, i);
        }

        static void ShowHelp()
        {
            Console.WriteLine("Commands:");
            Console.WriteLine("  encrypt <file> [key] [-d] [-f]  Encrypt file (generates key if omitted)");
            Console.WriteLine("  encrypt <file> -p [-d] [-f]     Encrypt with password");
            Console.WriteLine("  decrypt <file> <key> [-f]       Decrypt file");
            Console.WriteLine("  decrypt <file> -p [-f]          Decrypt with password");
            Console.WriteLine("  verify <file> <key>             Verify decryptability without output");
            Console.WriteLine("  verify <file> -p                Verify with password");
            Console.WriteLine("  keygen <keyfile> [-f]           Generate a key file");
            Console.WriteLine("  rekey <file> <old> <new> [-f]    Re-encrypt with new key");
            Console.WriteLine("  rekey <file> -p [-f]            Rekey password-based file");
            Console.WriteLine("  info [file]                     Show tool or file info");
            Console.WriteLine("  version               Show version");
            Console.WriteLine("  info                  Show tool info");
            Console.WriteLine("  ls                    List directory");
            Console.WriteLine("  cd <path>             Change directory");
            Console.WriteLine("  clear / cls           Clear screen");
            Console.WriteLine("  exit                  Exit program");
        }
    }
}
