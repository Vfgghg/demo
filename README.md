ekycOTPbased = "0",
                    segment = "3",
                    segmentStartDate = "11-Feb-2022",
                    status = "Active",
                    effectiveDate = "15-Nov-2022",
                    minor = "0",
                    maritalStatus = "M",
                    occupationType = "SE",
                    occupationTypeOther = "",
                    natureOfBusinessOther = "Marketing Firm",
                    companyIdentificationNumber = "",
                    companyRegistrationNumber = "",
                    companyRegistrationCountry = "",
                    globalIntermediaryIdentificationNumber = "",
                    kycAttestationType = "1",
                    kycDateOfDeclaration = "11-Mar-2021",
                    kycPlaceOfDeclaration = "Mumbai",
                    kycVerificationDate = "11-Mar-2021",
                    kycEmployeeName = "Aditi Jadhav",
                    kycEmployeeDesignation = "Manager",
                    kycVerificationBranch = "Mumbai",
                    kycEmployeeCode = "6546514",
                    listed = "",
                    applicationRefNumber = "AJNPC45568",
                    documentRefNumber = "DOCREF5722",
                    regAMLRisk = "1",
                    regAMLRiskLastRiskReviewDate = "21-Jan-2019",
                    regAMLRiskNextRiskReviewDate = "21-Mar-2025",
                    incomeRange = "2",
                    exactIncome = 250000.5,
                    incomeCurrency = "INR",
                    incomeEffectiveDate = "11-Feb-2022",
                    incomeDescription = "Total income of a month",
                    incomeDocument = "TaxReturns,CashFlowStatement",
                    exactNetworth = 1000000.0,
                    networthCurrency = "INR",
                    networthEffectiveDate = "11-Feb-2019",
                    networthDescription = "Total networth income of a year",
                    networthDocument = "NetworthCertificate, BalanceSheet",
                    familyCode = "FMC18779",
                    channel = "2",
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

