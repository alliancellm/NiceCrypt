using System;
using System.Security.Cryptography;

namespace NiceCrypt.Utils
{
    public static class SecureRandom
    {
        public static byte[] GenerateBytes(int count)
        {
            byte[] bytes = new byte[count];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }
    }
}
