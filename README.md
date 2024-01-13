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

******************
System.Collections.Generic.KeyNotFoundException: 'The given key '6360d110-8239-44a8-bb07-616a59a72565' was not present in the dictionary.'

public static string DecryptString(string sessionId, string cipherText)
{
    if (SessionKeys.ContainsKey(sessionId))
    {
        try
        {
            string sessionKey = SessionKeys[sessionId];

            using (Aes aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(sessionKey);
                aes.GenerateIV();

                ICryptoTransform decryptor = aes.CreateDecryptor();

                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
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
            Console.WriteLine($"Error during decryption: {ex.Message}\nStack Trace: {ex.StackTrace}");
        }
    }
    else
    {
        Console.WriteLine($"Session not found: {sessionId}");
    }

    return null; // Session not found or decryption error
}

***************
Session not found: 18ebea2d-3b56-46b2-a75a-f2641c761dfb
************************
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

        public static string StartSession() => SessionKeys[Guid.NewGuid().ToString()] = GenerateRandomKey();

        public static string EndSession(string sessionId) => SessionKeys.Remove(sessionId, out var sessionKey) ? sessionKey : null;

        public static string GenerateRandomKey()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] keyBytes = new byte[32];
                rng.GetBytes(keyBytes);
                return Convert.ToBase64String(keyBytes);
            }
        }

        public static string EncryptString(string sessionId, string plainText) =>
            Convert.ToBase64String(EncryptDecryptInternal(sessionId, plainText, true));

        public static string DecryptString(string sessionId, string cipherText) =>
            Encoding.UTF8.GetString(Convert.FromBase64String(EncryptDecryptInternal(sessionId, cipherText, false)));

        private static byte[] EncryptDecryptInternal(string sessionId, string input, bool encrypt)
        {
            var sessionKey = SessionKeys[sessionId];

            using (Aes aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(sessionKey);
                aes.GenerateIV();

                ICryptoTransform cryptoTransform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(input);
                    }

                    return memoryStream.ToArray();
                }
            }
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
            var sessionId = AesOperation.StartSession();

            Console.WriteLine($"Started Session ID: {sessionId}");

            Console.WriteLine("Please enter a string for encryption:");
            var str = Console.ReadLine();

            var encryptedString = AesOperation.EncryptString(sessionId, str);
            Console.WriteLine($"Encrypted string = {encryptedString}");

            byte[] keyBytes = Convert.FromBase64String(AesOperation.EndSession(sessionId));
            byte[] dataBytes = Encoding.UTF8.GetBytes(str);
            string hash = AesOperation.GenerateHash(keyBytes, dataBytes);
            Console.WriteLine($"Generated Hash = {hash}");

            try
            {
                Console.WriteLine($"Attempting to decrypt using Session ID: {sessionId}");
                var decryptedString = AesOperation.DecryptString(sessionId, encryptedString);
                Console.WriteLine($"Decrypted string = {decryptedString}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during decryption: {ex.Message}\nStack Trace: {ex.StackTrace}");
            }

            Console.ReadKey();
        }
    }
}



