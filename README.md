# demo

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionDecryptionUsingSymmetricKey
{
    public class AesOperation
    {
        public static string GenerateRandomKey()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] keyBytes = new byte[32]; // 256 bits
                rng.GetBytes(keyBytes);
                return Convert.ToBase64String(keyBytes);
            }
        }

        public static string EncryptString(string key, string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(key);
                aes.GenerateIV();

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }
                    }

                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
        }

        public static string DecryptString(string key, string cipherText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(key);
                aes.GenerateIV();

                ICryptoTransform decryptor = aes.CreateDecryptor();

                using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static string GenerateHash(string key, string data)
        {
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);

            using (HMACSHA256 hmac = new HMACSHA256(keyBytes))
            {
                byte[] hashBytes = hmac.ComputeHash(dataBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }
}





****

 public static string GenerateHash(byte[] key, byte[] data)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                byte[] hashBytes = hmac.ComputeHash(data);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var key = AesOperation.GenerateRandomKey();

            Console.WriteLine("Please enter a string for encryption:");
            var str = Console.ReadLine();

            // Encrypt the entered string using the key
            var encryptedString = AesOperation.EncryptString(key, str);
            Console.WriteLine($"Encrypted string = {encryptedString}");

            // Example of calling GenerateHash with raw byte arrays
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] dataBytes = Encoding.UTF8.GetBytes(str);
            string hash = AesOperation.GenerateHash(keyBytes, dataBytes);
            Console.WriteLine($"Generated Hash = {hash}");

            Console.ReadKey();
        }
    }
}
