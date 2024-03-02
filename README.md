using System;
using System.Security.Cryptography;
using System.Text;

public static class DecryptionHelper
{
    public static string DecryptData(byte[] encryptedData, RSAParameters privateKeyParameters)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(privateKeyParameters);
            byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}

********************************************
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

public static class ApiResponseHelper
{
    public static async Task ProcessResponse(HttpResponseMessage response, RSAParameters publicKeyParameters, RSAParameters privateKeyParameters)
    {
        if (response.IsSuccessStatusCode)
        {
            // Read the response content
            var responseData = await response.Content.ReadAsByteArrayAsync();

            // Extract the encrypted data and signature from the response headers
            string encryptedDataString = response.Headers.GetValues("EncryptedData").FirstOrDefault();
            string signatureString = response.Headers.GetValues("Signature").FirstOrDefault();

            if (string.IsNullOrEmpty(encryptedDataString) || string.IsNullOrEmpty(signatureString))
            {
                // Handle missing encrypted data or signature
                Console.WriteLine("Error: EncryptedData or Signature header missing in the response.");
                return;
            }

            // Convert the encrypted data and signature from Base64 strings to byte arrays
            byte[] encryptedData = Convert.FromBase64String(encryptedDataString);
            byte[] signature = Convert.FromBase64String(signatureString);

            // Verify the signature
            bool signatureValid = SignatureHelper.VerifySignature(encryptedData, signature, publicKeyParameters);

            if (signatureValid)
            {
                // Decrypt the data if the signature is valid
                string decryptedData = DecryptionHelper.DecryptData(encryptedData, privateKeyParameters);

                // Process the decrypted data...
                Console.WriteLine("Decrypted data:");
                Console.WriteLine(decryptedData);
            }
            else
            {
                // Handle invalid signature
                Console.WriteLine("Error: Invalid signature.");
            }
        }
        else
        {
            // Handle non-success status code
            Console.WriteLine($"Error: API request failed with status code {response.StatusCode}.");
        }
    }
}
*************************
   using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(publicKey);

            encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(serializedData), RSAEncryptionPadding.OaepSHA256);
        }

        return encryptedData;
    }
}
