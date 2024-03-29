using CustomerDataFields;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Helperclass
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Create a new instance of it and initialize its properties
            MainRequestDataField obj1 = new MainRequestDataField
            {
                RequestedID = "IND2550",
                SourceSystemName = "FINACLE",
                Purpose = "01",

            };

            // useage
            Console.WriteLine($"RequestId: {obj1.RequestedID}");
            Console.WriteLine($"SourceSystemName: {obj1.SourceSystemName}");
            Console.WriteLine($"Purpose: {obj1.Purpose}");
           
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

