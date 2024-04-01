using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace RequestResponse
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string publicKeyCertificatePath = "H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\public.cer";
            string privateKeyCertificatePath = "H:\\Temporary\\Vaibhav.Soni\\Marwadi\\server\\private.pfx";
            string privateKeyCertificatePassword = "test@123";

            X509Certificate2 publicKeyCertificate = new X509Certificate2(publicKeyCertificatePath);
            X509Certificate2 privateKeyCertificate = new X509Certificate2(privateKeyCertificatePath, privateKeyCertificatePassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            RSAParameters publicKeyParameters = ((RSA)publicKeyCertificate.GetRSAPublicKey()).ExportParameters(false);
            RSA privateKey = privateKeyCertificate.GetRSAPrivateKey();

            string textToEncrypt = GenerateTestString();
            Console.WriteLine($"Text to encrypt: {textToEncrypt}");

            byte[] signature = Signature.SignData(Encoding.UTF8.GetBytes(textToEncrypt), privateKeyCertificate);
            Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");

            byte[] encryptedBytes = Encryption.Encrypt(Encoding.UTF8.GetBytes(textToEncrypt), publicKeyParameters);
            string encryptedText = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine($"Encrypted text: {encryptedText}");

            string decryptedText = DecryptionHelper.DecryptData(Convert.FromBase64String(encryptedText), privateKeyCertificate);
            Console.WriteLine($"Decrypted text: {decryptedText}");

            bool signatureValid = Signature.VerifySignature(Encoding.UTF8.GetBytes(decryptedText), signature, publicKeyCertificate);
            Console.WriteLine($"Signature is valid: {signatureValid}");

            // Integration point: Make the API request and handle the response
            string endpoint = "application/json";
            string method = "post";
            string url = "https://tenantdev1.tssconsultancy.com:5309";
            string requestData = "{\"key\": \"value\"}"; // Replace this with your actual request data

            try
            {
                // Make the API request
                var response = await AS501APIRequest.MakeRequest(endpoint, method, url, requestData);

                // Handle the response
                if (response.IsSuccessStatusCode)
                {
                    string responseBody = await AS501APIResponse.HandleResponse(response);
                    Console.WriteLine($"Response received: {responseBody}");
                }
                else
                {
                    Console.WriteLine($"Request failed with status code {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        public static string GenerateTestString()
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
    }
}

namespace Request
{
    public class AS501APIRequest
    {
        public static async Task<HttpResponseMessage> MakeRequest(string endpoint, string method, string url, string data = "CL1_User")
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("cluster", "CL1_User");
            client.DefaultRequestHeaders.Add("Domain", "https://tenantdev1.tssconsultancy.com:5309");
            client.DefaultRequestHeaders.Add("ApiToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcGlTdWJzY3JpcHRpb25JZCI6IjEiLCJUZW5hbnAJZGVu");
            client.DefaultRequestHeaders.Add("Content-Type", "application/json");

            string fullUrl = url + endpoint;

            HttpResponseMessage response;
            switch (method.ToLower())
            {
                case "get":
                    response = await client.GetAsync(fullUrl);
                    break;
                case "post":
                    var content = new StringContent(data, Encoding.UTF8, "application/json");
                    response = await client.PostAsync(fullUrl, content);
                    break;
                default:
                    throw new ArgumentException($"Unsupported HTTP method: {method}");
            }

            return response;
        }
    }
}

namespace Response
{
    public class AS501APIResponse
    {
        public static async Task<string> HandleResponse(HttpResponseMessage response)
        {
            string responseBody = await response.Content.ReadAsStringAsync();
            return responseBody;
        }
    }
}
