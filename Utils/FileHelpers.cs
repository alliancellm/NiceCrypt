using System;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;

namespace NiceCrypt.Utils
{
    public static class FileHelpers
    {
        public static void TryRestrictFilePermissions(string path)
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return;
                }

#if NET6_0_OR_GREATER
                File.SetUnixFileMode(
                    path,
                    UnixFileMode.UserRead |
                    UnixFileMode.UserWrite);
#endif
            }
            catch
            {
                // Best effort; do not block.
            }
        }
        public static byte[] ReadAllBytesWithProgress(
            string path,
            Action<long, long>? progress,
            CancellationToken cancellationToken = default)
        {
            long length = new FileInfo(path).Length;
            if (length > int.MaxValue)
                throw new NotSupportedException("File too large for single-pass GCM operation (Limit: 2GB).");

            byte[] buffer = new byte[length];
            long totalRead = 0;

            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                int read;
                while ((read = fs.Read(buffer, (int)totalRead, (int)Math.Min(1024 * 1024, length - totalRead))) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    totalRead += read;
                    progress?.Invoke(totalRead, length);
                }
            }

            return buffer;
        }

        public static void AtomicWrite(string path, byte[] data)
        {
            string tempPath = path + ".tmp_" + Guid.NewGuid().ToString();
            try
            {
                using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    fs.Write(data, 0, data.Length);
                    fs.Flush(true);
                }
                AtomicMove(tempPath, path);
            }
            catch
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
                throw;
            }
        }

        public static void AtomicMove(string source, string dest)
        {
            File.Move(source, dest, overwrite: true);
        }

        public static string BytesToString(long byteCount)
        {
            string[] suf = { "B", "KB", "MB", "GB", "TB" };
            if (byteCount == 0) return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 1);
            return (Math.Sign(byteCount) * num).ToString() + suf[place];
        }
    }
}
