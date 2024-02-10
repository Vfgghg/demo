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




This is RSA
