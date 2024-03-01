encption::----
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RES_LEARN
{
    public static class Encryption
    {
        public static byte[] Encrypt(byte[] data, string publicKeyFilePath)
        {
            X509Certificate2 publicKeyCertificate = new X509Certificate2(publicKeyFilePath);
            RSAParameters publicKeyParameters = ((RSA)publicKeyCertificate.GetRSAPublicKey()).ExportParameters(false);

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKeyParameters);
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }
    }
}




decption:::----

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RES_LEARN
{
    public static class Decryption
    {
        public static string Decrypt(byte[] encryptedData, string privateKeyFilePath, string privateKeyPassword)
        {
            X509Certificate2 privateKeyCertificate = new X509Certificate2(privateKeyFilePath, privateKeyPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
            RSAParameters privateKeyParameters = ((RSA)privateKeyCertificate.GetRSAPrivateKey()).ExportParameters(true);

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKeyParameters);
                byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }
    }
}


signature::----

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RES_LEARN
{
    public static class Signature
    {
        public static byte[] SignData(byte[] data, string privateKeyFilePath, string privateKeyPassword)
        {
            X509Certificate2 privateKeyCertificate = new X509Certificate2(privateKeyFilePath, privateKeyPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            using (RSA rsa = (RSA)privateKeyCertificate.GetRSAPrivateKey())
            {
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static bool VerifySignature(byte[] data, byte[] signature, string publicKeyFilePath)
        {
            X509Certificate2 publicKeyCertificate = new X509Certificate2(publicKeyFilePath);
            
            using (RSA rsa = (RSA)publicKeyCertificate.GetRSAPublicKey())
            {
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}

***********************execute file
public class Program
{
    public static void Main(string[] args)
    {
        // Specify the paths to your public and private key files
        string publicKeyFilePath = "path_to_public_key";
        string privateKeyFilePath = "path_to_private_key";
        string privateKeyPassword = "your_private_key_password"; // Only if private key is password protected

        // Sample data to encrypt
        string dataToEncrypt = "Hello, world!";
        byte[] dataBytes = Encoding.UTF8.GetBytes(dataToEncrypt);

        // Load the public key from file
        using (RSA rsaEncryption = RSA.Create())
        {
            // Read the public key from file
            byte[] publicKeyBytes = File.ReadAllBytes(publicKeyFilePath);
            rsaEncryption.ImportFromPem(publicKeyBytes, out _);

            // Encrypt the data using the public key
            byte[] encryptedData = EncryptionHelper.EncryptData(dataBytes, rsaEncryption);

            // Output the encrypted data
            Console.WriteLine("Encrypted data: " + Convert.ToBase64String(encryptedData));
        }

        // Load the private key from file
        using (RSA rsaDecryption = RSA.Create())
        {
            // Read the private key from file
            byte[] privateKeyBytes = File.ReadAllBytes(privateKeyFilePath);
            rsaDecryption.ImportFromPem(privateKeyBytes, out _);

            // Decrypt the encrypted data using the private key
            byte[] decryptedData = DecryptionHelper.DecryptData(encryptedData, rsaDecryption);

            // Convert the decrypted bytes back to a string
            string decryptedString = Encoding.UTF8.GetString(decryptedData);

            // Output the decrypted data
            Console.WriteLine("Decrypted data: " + decryptedString);
        }
    }
}



This is RSA
