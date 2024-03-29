using System;
using System.Security.Cryptography;
using System.Text;

public class RSAEncryption
{
    public static string Decrypt(string data, RSAParameters privateKey)
    {
        byte[] encryptedBytes = Convert.FromBase64String(data);

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(privateKey);
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, true);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}

===================
using System;
using System.Security.Cryptography;
using System.Text;

public class RSAEncryption
{
    public static string Encrypt(string data, RSAParameters publicKey)
    {
        byte[] bytesToEncrypt = Encoding.UTF8.GetBytes(data);

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(publicKey);
            byte[] encryptedBytes = rsa.Encrypt(bytesToEncrypt, true);
            return Convert.ToBase64String(encryptedBytes);
        }
    }
}
======================
using System;
using System.Security.Cryptography;
using System.Text;

public class RSASignature
{
    public static byte[] SignData(string data, RSAParameters privateKey)
    {
        byte[] bytesToSign = Encoding.UTF8.GetBytes(data);

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(privateKey);
            return rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public static bool VerifyData(string data, byte[] signature, RSAParameters publicKey)
    {
        byte[] bytesToVerify = Encoding.UTF8.GetBytes(data);

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(bytesToVerify, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}

