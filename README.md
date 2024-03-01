using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;

public class Program
{
    public static async Task Main(string[] args)
    {
        // 1. Create the request data
        MainRequestDataField requestData = CreateRequestData();

        // 2. Encrypt the request data
        byte[] encryptedData = EncryptionHelper.EncryptData(requestData);

        // 3. Sign the encrypted data
        byte[] signature = SignatureHelper.SignData(encryptedData);

        // 4. Send the encrypted data and signature to the API
        HttpResponseMessage response = await ApiHelper.SendRequestToApi(encryptedData, signature);

        // 5. Process the response from the API
        await ResponseProcessor.ProcessResponse(response);
    }

    private static MainRequestDataField CreateRequestData()
    {
        return new MainRequestDataField
        {
            RequestedID = "123456",
            SourceSystemName = SourceSystemNameEnum.System1,
            APItoken = "your_api_token",
            Purpose = PurposeEnum.Purpose1,
            SessionKey = "session_key"
        };
    }
}

public class MainRequestDataField
{
    public string RequestedID { get; set; }
    public SourceSystemNameEnum SourceSystemName { get; set; }
    public string APItoken { get; set; }
    public PurposeEnum Purpose { get; set; }
    public string SessionKey { get; set; }
}

public enum SourceSystemNameEnum
{
    System1,
    System2,
    System3
}

public enum PurposeEnum
{
    Purpose1,
    Purpose2,
    Purpose3
}

public static class EncryptionHelper
{
    public static byte[] EncryptData(MainRequestDataField requestData)
    {
        string serializedRequest = JsonSerializer.Serialize(requestData);
        // Implement encryption logic here (e.g., using AES)
        byte[] encryptedData = Encoding.UTF8.GetBytes(serializedRequest); // Placeholder
        return encryptedData;
    }
}

public static class SignatureHelper
{
    public static byte[] SignData(byte[] encryptedData)
    {
        // Implement signing logic here (e.g., using RSA)
        using (RSA rsa = RSA.Create())
        {
            // Load private key from file or other source
            // rsa.ImportParameters(privateKeyParameters);

            // Sign the encrypted data
            return rsa.SignData(encryptedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}

public static class ApiHelper
{
    public static async Task<HttpResponseMessage> SendRequestToApi(byte[] encryptedData, byte[] signature)
    {
        // Implement API request logic to send encryptedData and signature
        HttpClient client = new HttpClient();
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com");
        request.Content = new ByteArrayContent(encryptedData);
        request.Headers.Add("X-Signature", Convert.ToBase64String(signature));
        HttpResponseMessage response = await client.SendAsync(request);
        return response;
    }
}

public static class ResponseProcessor
{
    public static async Task ProcessResponse(HttpResponseMessage response)
    {
        // Implement response processing logic here
        if (response.IsSuccessStatusCode)
        {
            byte[] responseData = await response.Content.ReadAsByteArrayAsync();
            // Decrypt and process the response data
        }
        else
        {
            // Handle error response
        }
    }
}

imp part!!above

********************************************************************
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using System.Text;

namespace RES_LEARN
{
    class Program
    {

        static void Main(string[] args)
        {
            // Specify the paths to your certificate files
            string publicKeyCertificatePath = "H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\public.cer";
            string privateKeyCertificatePath = "H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\private.pfx";
            string privateKeyCertificatePassword = "marwadi";

            // Load public key certificate
            X509Certificate2 publicKeyCertificate = new X509Certificate2("H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\public.cer");

            // Load private key certificate
            X509Certificate2 privateKeyCertificate = new X509Certificate2("H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\private.pfx", "test@123", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            // Extract RSA parameters from certificate
            RSAParameters publicKeyParameters = ((RSA)publicKeyCertificate.GetRSAPublicKey()).ExportParameters(false);
            RSAParameters privateKeyParameters = ((RSA)privateKeyCertificate.GetRSAPrivateKey()).ExportParameters(true);


            string publicKeyString = GetKeyString(publicKeyParameters);
            string privateKeyString = GetKeyString(privateKeyParameters);

            Console.WriteLine("PUBLIC KEY: ");
            Console.WriteLine(publicKeyString);
            Console.WriteLine("-------------------------------------------");

            Console.WriteLine("PRIVATE KEY: ");
            Console.WriteLine(privateKeyString);
            Console.WriteLine("-------------------------------------------");

            string textToEncrypt = GenerateTestString();
            Console.WriteLine("TEXT TO ENCRYPT: ");
            Console.WriteLine(textToEncrypt);
            Console.WriteLine("-------------------------------------------");

            // Sign the data before encryption
            byte[] signature = SignData(Encoding.UTF8.GetBytes(textToEncrypt), privateKeyCertificate);

            byte[] encryptedBytes = Encrypt(Encoding.UTF8.GetBytes(textToEncrypt), publicKeyParameters);
            string encryptedText = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine("ENCRYPTED TEXT: ");
            Console.WriteLine(encryptedText);
            Console.WriteLine("-------------------------------------------");

            string decryptedText = Decrypt(Convert.FromBase64String(encryptedText), privateKeyParameters);
            // Verify the signature after decryption
            bool signatureValid = VerifySignature(Encoding.UTF8.GetBytes(decryptedText), signature, publicKeyCertificate);
            Console.WriteLine("SIGNATURE VALIDITY: ");
            Console.WriteLine(signatureValid ? "Valid" : "Invalid");
            Console.WriteLine("-------------------------------------------");

            Console.WriteLine("DECRYPTED TEXT: ");
            Console.WriteLine(decryptedText);

            Console.WriteLine("press any key to exit");
            Console.ReadKey();
        }

        public static string GetKeyString(RSAParameters publicKey)
        {
            var stringWriter = new StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, publicKey);
            return stringWriter.ToString();
        }

        public static byte[] Encrypt(byte[] data, RSAParameters publicKeyParameters)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKeyParameters);
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }

        public static string Decrypt(byte[] encryptedData, RSAParameters privateKeyParameters)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKeyParameters);
                byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }

        private static string GenerateTestString()
        {
            Guid opportunityId = Guid.NewGuid();
            Guid systemUserId = Guid.NewGuid();
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("opportunityid={0}", opportunityId.ToString());
            sb.AppendFormat("&systemuserid={0}", systemUserId.ToString());
            sb.AppendFormat("&currenttime={0}", currentTime);

            return sb.ToString();
        }
        public static byte[] SignData(byte[] data, X509Certificate2 certificate)
        {
            using (RSA rsa = (RSA)certificate.GetRSAPrivateKey())
            {
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static bool VerifySignature(byte[] data, byte[] signature, X509Certificate2 certificate)
        {
            using (RSA rsa = (RSA)certificate.GetRSAPublicKey())
            {
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}

