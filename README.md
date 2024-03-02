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
    public static byte[] EncryptData(MainRequestDataField requestData, byte[] key, byte[] iv)
    {
        // Serialize the request data to JSON
        string serializedRequest = JsonSerializer.Serialize(requestData);

        // Convert the serialized JSON string to a byte array
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(serializedRequest);

        // Create AES encryption algorithm instance
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create an encryptor to perform the stream transform
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create a memory stream to store the encrypted data
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // Create a CryptoStream to perform encryption
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    // Write the plaintext data to the CryptoStream
                    csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                    csEncrypt.FlushFinalBlock();

                    // Return the encrypted data as a byte array
                    return msEncrypt.ToArray();
                }
            }
        }
    }
}
