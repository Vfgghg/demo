using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;

public static class ApiRequestHelper
{
    public static async Task<HttpResponseMessage> SendEncryptedAndSignedRequestToApi(string data, RSAParameters publicKeyParameters, RSAParameters privateKeyParameters)
    {
        // Encrypt the data using EncryptionHelper
        byte[] encryptedData = EncryptionHelper.EncryptData(data, publicKeyParameters);

        // Sign the encrypted data using SignatureHelper
        byte[] signature = SignatureHelper.SignData(encryptedData, privateKeyParameters);

        // Send the encrypted data and signature to the API
        return await SendRequestToApi(encryptedData, signature);
    }

    private static async Task<HttpResponseMessage> SendRequestToApi(byte[] encryptedData, byte[] signature)
    {
        using (HttpClient client = new HttpClient())
        {
            // Configure the base URL of the API
            client.BaseAddress = new Uri("https://api.example.com");

            // Construct the request body
            var requestData = new
            {
                EncryptedData = Convert.ToBase64String(encryptedData),
                Signature = Convert.ToBase64String(signature)
            };

            // Send the POST request to the API endpoint
            HttpResponseMessage response = await client.PostAsJsonAsync("/endpoint", requestData);
            return response;
        }
    }
}
*******************
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public static class EncryptionHelper
{
    public static byte[] EncryptData(object data, byte[] key, byte[] iv)
    {
        string serializedData = JsonSerializer.Serialize(data);
        byte[] encryptedData;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(serializedData);
                    }
                    encryptedData = msEncrypt.ToArray();
                }
            }
        }

        return encryptedData;
    }
}

