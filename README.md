using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class SecureAsymmetricEncryption
{
    public static byte[] Encrypt(string publicKeyPath, string plainText)
    {
        using (RSA rsa = RSA.Create())
        {
            // Load the public key from the certificate
            X509Certificate2 certificate = new X509Certificate2(publicKeyPath);

            // Ensure the certificate is valid and has a public key
            if (certificate.NotAfter < DateTime.Now || certificate.PublicKey.Key == null)
            {
                throw new InvalidOperationException("Invalid certificate");
            }

            RSAParameters publicKeyParameters = certificate.GetRSAPublicKey().ExportParameters(false);
            rsa.ImportParameters(publicKeyParameters);

            // Encrypt the data
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }
    }

    public static string Decrypt(string privateKeyPath, string privateKeyPassword, byte[] encryptedData)
    {
        using (RSA rsa = RSA.Create())
        {
            // Load the private key from the certificate
            X509Certificate2 certificate = new X509Certificate2(privateKeyPath, privateKeyPassword, X509KeyStorageFlags.Exportable);

            // Ensure the certificate is valid and has a private key
            if (certificate.NotAfter < DateTime.Now || certificate.PrivateKey == null)
            {
                throw new InvalidOperationException("Invalid certificate");
            }

            RSAParameters privateKeyParameters = ((RSA)certificate.PrivateKey).ExportParameters(true);
            rsa.ImportParameters(privateKeyParameters);

            // Decrypt the data
            byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }

    public static string ExportPublicKey(string publicKeyPath)
    {
        X509Certificate2 certificate = new X509Certificate2(publicKeyPath);
        RSAParameters publicKeyParameters = certificate.GetRSAPublicKey().ExportParameters(false);
        return ExportKey(publicKeyParameters);
    }

    public static string ExportPrivateKey(string privateKeyPath, string privateKeyPassword)
    {
        X509Certificate2 certificate = new X509Certificate2(privateKeyPath, privateKeyPassword, X509KeyStorageFlags.Exportable);
        RSAParameters privateKeyParameters = ((RSA)certificate.PrivateKey).ExportParameters(true);
        return ExportKey(privateKeyParameters);
    }

    private static string ExportKey(RSAParameters keyParameters)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(keyParameters);
            return Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        }
    }
}

class Program
{
    static void Main()
    {
        try
        {
            // Example usage
            string publicKeyPath = @"path_to_public_certificate.cer";
            string privateKeyPath = @"path_to_private_certificate.pfx";
            string privateKeyPassword = "password";
            string plainText = "Hello, world!";

            // Encryption
            byte[] encryptedData = SecureAsymmetricEncryption.Encrypt(publicKeyPath, plainText);
            Console.WriteLine($"Encrypted Data: {Convert.ToBase64String(encryptedData)}");

            // Decryption
            string decryptedText = SecureAsymmetricEncryption.Decrypt(privateKeyPath, privateKeyPassword, encryptedData);
            Console.WriteLine($"Decrypted Text: {decryptedText}");

            // Export Public Key
            string exportedPublicKey = SecureAsymmetricEncryption.ExportPublicKey(publicKeyPath);
            Console.WriteLine($"Exported Public Key:\n{exportedPublicKey}");

            // Export Private Key
            string exportedPrivateKey = SecureAsymmetricEncryption.ExportPrivateKey(privateKeyPath, privateKeyPassword);
            Console.WriteLine($"Exported Private Key:\n{exportedPrivateKey}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
