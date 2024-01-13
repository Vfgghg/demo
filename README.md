using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionDecryptionUsingSymmetricKey
{
    public class AesOperation
    {
        private static readonly Dictionary<string, string> SessionKeys = new Dictionary<string, string>();

        public static string StartSession()
        {
            string sessionId = Guid.NewGuid().ToString();
            string sessionKey = GenerateRandomKey();
            SessionKeys.Add(sessionId, sessionKey);
            return sessionId;
        }

        public static void EndSession(string sessionId)
        {
            SessionKeys.Remove(sessionId);
        }

        public static string GenerateRandomKey()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] keyBytes = new byte[32]; // 256 bits
                rng.GetBytes(keyBytes);
                return Convert.ToBase64String(keyBytes);
            }
        }

        public static string EncryptString(string sessionId, string plainText)
        {
            if (SessionKeys.TryGetValue(sessionId, out string sessionKey))
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = Convert.FromBase64String(sessionKey);
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

            return null; // Session not found
        }

        public static string DecryptString(string sessionId, string cipherText)
        {
            if (SessionKeys.TryGetValue(sessionId, out string sessionKey))
            {
                try
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = Convert.FromBase64String(sessionKey);
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
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during decryption: {ex.Message}");
                }
            }

            return null; // Session not found or decryption error
        }

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
            // Start a new session and get the session identifier
            var sessionId = AesOperation.StartSession();

            Console.WriteLine("Please enter a string for encryption:");
            var str = Console.ReadLine();

            // Encrypt the entered string using the session key
            var encryptedString = AesOperation.EncryptString(sessionId, str);
            Console.WriteLine($"Encrypted string = {encryptedString}");

            // Example of calling GenerateHash with raw byte arrays
            byte[] keyBytes = Convert.FromBase64String(AesOperation.SessionKeys[sessionId]);
            byte[] dataBytes = Encoding.UTF8.GetBytes(str);
            string hash = AesOperation.GenerateHash(keyBytes, dataBytes);
            Console.WriteLine($"Generated Hash = {hash}");

            // Decrypt the string using the session key
            var decryptedString = AesOperation.DecryptString(sessionId, encryptedString);

            // Display the decrypted string
            Console.WriteLine($"Decrypted string = {decryptedString}");

            // End the session
            AesOperation.EndSession(sessionId);

            Console.ReadKey();
        }
    }
}
