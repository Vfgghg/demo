using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;


class Program
{
    private static RSAParameters publicKey;
    private static RSAParameters privateKey;
    public enum KeySizes
    {
        SIZE_512 = 512,
        SIZE_1024 = 1024,
        SIZE_2048 = 2048,
        SIZE_952 = 952,
        SIZE_1369 = 1369
    }

    public static string Message; //text to be encrypted
    public static List<byte[]> Encrypted_Texts_Array = new List<byte[]>(); //store encrypted texts


    public static void AppendAllBytes(string path, byte[] bytes)
    {
        using (var stream = new FileStream(path, FileMode.Append))
        {
            stream.Write(bytes, 0, bytes.Length);
        }
    }

    static void Main(string[] args)
    {
        Console.WriteLine("Write message to be encrypted:");

        Program.Message = Console.ReadLine();

        StartEncrypto();

        StartDecrypto();

        Console.ReadLine();
    }

    static void StartEncrypto()
    {

        //get text size
        int Text_Size = System.Text.ASCIIEncoding.ASCII.GetByteCount(Program.Message);
        Console.WriteLine("Text Size: " + Text_Size + " bytes");

        generateKeys();

        //encrypt message in chunks of 250 bytes then store result in file, separated by line breaks
        File.WriteAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\encrypted.txt", "");
        int Chunk_Size = 199;

        for (int i = 0; i < Math.Ceiling(Text_Size / (Chunk_Size * 1.0)); i++)
        {
            try
            {
                byte[] Encrypted_Text = Encrypt(Encoding.UTF8.GetBytes(Program.Message.Substring(i * Chunk_Size, Chunk_Size)));

                File.AppendAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\encrypted.txt", Convert.ToBase64String(Encrypted_Text) + "\n");

                Program.Encrypted_Texts_Array.Add(Encrypted_Text);
            }
            catch (System.Exception)
            {
                byte[] Encrypted_Text = Encrypt(Encoding.UTF8.GetBytes(Program.Message.Substring(i * Chunk_Size)));

                File.AppendAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\encrypted.txt", Convert.ToBase64String(Encrypted_Text) + "\n");

                Program.Encrypted_Texts_Array.Add(Encrypted_Text);
            }

        }

        Console.WriteLine("Encrypted data written to file\n");
    }


    static void StartDecrypto()
    {

        List<byte[]> Decrypted_Texts = new List<byte[]>();

        //read encrypted data from file line by line and decrypt it
        string line;

        System.IO.StreamReader file = new System.IO.StreamReader(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\encrypted.txt");

        while ((line = file.ReadLine()) != null)
        {
            byte[] from_file = Convert.FromBase64String(line);
            byte[] decrypted = Decrypt(from_file);

            Decrypted_Texts.Add(decrypted);
        }
        file.Close();


        Console.WriteLine("Encrypted data from file read and decrypted\n");


        Console.WriteLine("Original\n\t " + Program.Message + "\n");

        string collect = "";
        foreach (var item in Program.Encrypted_Texts_Array)
        {
            collect += BitConverter.ToString(item).Replace("-", "") + "\n";
        }
        Console.WriteLine("Encrypted\n\t" + collect);

        Console.WriteLine("Decrypted\n\t");
        foreach (var chunk in Decrypted_Texts)
        {
            Console.Write(Encoding.UTF8.GetString(chunk));
        }
        Console.WriteLine("");
    }



    static void generateKeys()
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false; //Don't store the keys in a key container
            publicKey = rsa.ExportParameters(false);
            privateKey = rsa.ExportParameters(true);

            //store the keys in file
            File.WriteAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\pubKey.xml", KeyToString(publicKey));
            File.WriteAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\priKey.xml", KeyToString(privateKey));

            Console.WriteLine("Keys writen to file\n");
        }
    }

    static byte[] Encrypt(byte[] input)
    {
        byte[] encrypted;
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            //get public key from file
            rsa.ImportParameters(StringToKey(File.ReadAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\pubKey.xml")));

            try
            {
                encrypted = rsa.Encrypt(input, true);
                return encrypted;
            }
            catch (System.Exception e)
            {
                System.Console.WriteLine(e);
                byte[] empty = {};
                return empty;
            }

        }
        
    }

    static byte[] Decrypt(byte[] input)
    {
        byte[] decrypted;
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            //get private key from file
            rsa.ImportParameters(StringToKey(File.ReadAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\priKey.xml")));

            try
            {
                decrypted = rsa.Decrypt(input, true);
                return decrypted;
            }
            catch (System.Exception e)
            {
                System.Console.WriteLine(e);
                byte[] empty = {};
                return empty;
            }
            
        }
        
    }

    //converting the public key into a string representation
    static string KeyToString(RSAParameters key)
    {
        //we need some buffer
        var sw = new System.IO.StringWriter();
        //we need a serializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //serialize the key into the stream
        xs.Serialize(sw, key);
        //get the string from the stream

        return sw.ToString();
    }

    //converting it back
    static RSAParameters StringToKey(string stringkey)
    {
        //get a stream from the string
        var sr = new System.IO.StringReader(stringkey);
        //we need a deserializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //get the object back from the stream

        return (RSAParameters)xs.Deserialize(sr);
    }
}
*********
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace first 
{
    public class AesOperation
    {
        internal static readonly Dictionary<string, string> SessionKeys = new Dictionary<string, string>();

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
}
******************
public static string EncryptString(string sessionId, string plainText)
{
    if (SessionKeys.TryGetValue(sessionId, out string sessionKey))
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Convert.FromBase64String(sessionKey);
            aes.GenerateIV();

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                }

                // Concatenate IV to the ciphertext for later use in decryption
                byte[] ivWithCiphertext = aes.IV.Concat(memoryStream.ToArray()).ToArray();
                return Convert.ToBase64String(ivWithCiphertext);
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

                // Extract IV from the beginning of the ciphertext
                byte[] iv = new byte[16];
                Buffer.BlockCopy(Convert.FromBase64String(cipherText), 0, iv, 0, iv.Length);
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

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
            return $"Error during decryption: {ex.Message}";
        }
    }

    return null; // Session not found or decryption error
}

