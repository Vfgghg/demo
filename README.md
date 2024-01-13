public static string DecryptString(string sessionId, string cipherText)
{
    // Retrieve the session key directly, assuming the session ID exists
    string sessionKey = SessionKeys[sessionId];

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
        return $"Error during decryption: {ex.Message}\nStack Trace: {ex.StackTrace}";
    }
}


                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
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

        public static string GenerateHash(byte[] key, byte[] data)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                byte[] hashBytes = hmac.ComputeHash(data);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }
}

*************************

using first;
using System;
using System.Text;

namespace first
{
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
  // Decrypt the string using the session key
            try
            {
                var decryptedString = AesOperation.DecryptString(sessionId, encryptedString);
                Console.WriteLine($"Decrypted string = {decryptedString}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during decryption: {ex.Message}");
            }

            Console.ReadKey();
        }
    }
}


****************************************

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionDecryptionUsingSymmetricKey
{
    public class AesOperation
    {
        // This dictionary will store session keys for each session identifier
        private static readonly Dictionary<string, string> SessionKeys = new Dictionary<string, string>();

        public static string StartSession()
        {
            // Generate a session identifier (you may use a more complex logic)
            string sessionId = Guid.NewGuid().ToString();
            
            // Generate a session key for the current session
            string sessionKey = GenerateRandomKey();

            // Store the session key with the session identifier
            SessionKeys.Add(sessionId, sessionKey);

            // Return the session identifier
            return sessionId;
        }

        public static string EndSession(string sessionId)
        {
            // Remove the session key when the session ends
            if (SessionKeys.ContainsKey(sessionId))
            {
                string sessionKey = SessionKeys[sessionId];
                SessionKeys.Remove(sessionId);
                return sessionKey;
            }

            return null; // Session not found
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

            return null; // Session not found
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
            byte[] keyBytes = Convert.FromBase64String(AesOperation.EndSession(sessionId));
            byte[] dataBytes = Encoding.UTF8.GetBytes(str);
            string hash = AesOperation.GenerateHash(keyBytes, dataBytes);
            Console.WriteLine($"Generated Hash = {hash}");

            Console.ReadKey();
        }
    }
}


***********************

public static string DecryptString(string sessionId, string cipherText)
{
    try
    {
        Console.WriteLine($"DecryptString: Session ID: {sessionId}, Cipher Text: {cipherText}");

        if (SessionKeys.TryGetValue(sessionId, out string sessionKey))
        {
            Console.WriteLine($"DecryptString: Session Key: {sessionKey}");

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

        // If the session is not found or expired, you may want to throw an exception or handle it appropriately.
        throw new Exception("Session not found or expired");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error during decryption: {ex.Message}\nStack Trace: {ex.StackTrace}");
        return null; // Handle the error gracefully in your application
    }
}
