using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security;
using AxTINYLib;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.IO;
using System.Net.Sockets;
using System.Net;

namespace DBSec
{
    class Utility
    {
        public static SecureString passPhrase = ToSecureString("AReallyStr0ngK#y4You"); /*= System.Text.Encoding.Unicode.GetBytes("Salt Is Not A Password");*/
        public static string DbName;
        public static string ftpAddress= "ftp://bastanisoft.ir/";

        // 
        // //public static AxTiny Tn = new AxTiny();
        public static string MakeConnectionStr(string address, string db, SecureString pass,string user="sa")

        {
           
            return string.Format(string.Format(@"Password={0};Persist Security Info=True;User ID={3};Initial Catalog={1};Data Source={2}",Utility.ToInsecureString(pass).Trim(), db.Trim(), address.Trim(),user));
        }
        public static async Task<string> TestDbConnection(string connstr)
        {
            using (SqlConnection conn = new SqlConnection(connstr))

            {
                try
                {
                    await conn.OpenAsync();
                    return "Ok";
                }
                catch (Exception ex)
                {
                    return ex.Message;
                }

            }
        }

        // public static string EncryptString(System.Security.SecureString input)
        // {
        //     byte[] encryptedData = System.Security.Cryptography.ProtectedData.Protect(System.Text.Encoding.Unicode.GetBytes(ToInsecureString(input)),
        //         entropy,
        //         System.Security.Cryptography.DataProtectionScope.CurrentUser);
        //     return Convert.ToBase64String(encryptedData);
        // }

        // public static SecureString DecryptString(string encryptedData)
        // {
        //     try
        //     {
        //         byte[] decryptedData = System.Security.Cryptography.ProtectedData.Unprotect(
        //             Convert.FromBase64String(encryptedData),
        //             entropy,
        //             System.Security.Cryptography.DataProtectionScope.CurrentUser);
        //         return ToSecureString(System.Text.Encoding.Unicode.GetString(decryptedData));
        //     }
        //     catch
        //     {
        //         return new SecureString();
        //     }
        // }

        public static SecureString ToSecureString(string input)
        {
            SecureString secure = new SecureString();
            foreach (char c in input)
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }

        public static string ToInsecureString(SecureString input)
        {
            string returnValue = string.Empty;
            IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(input);
            try
            {
                returnValue = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(ptr);
            }
            return returnValue;
        }



        public static SecureString DBPass;
        private const int Keysize = 256;
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText)
        {
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(ToInsecureString(passPhrase), saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(ToInsecureString(passPhrase), saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }
        public static string CheckTheFtpConnection(string address, string userName = "Bastanis", string password = "y!3d@7L4EvfYG4")
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Credentials = new NetworkCredential(userName, password);
                    
                    client.OpenRead(address);
                    client.Dispose();
                    return "Ok";

                }
            }
            catch(Exception ex)
            { return ex.Message; }
        }
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
        public static async Task<string> PutFileInFTP(string localFilePath, SecureString password,SecureString pharmacySerial, string address = "ftp://bastanisoft.ir/upload/", string userName = "Bastanis")
        {

            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Credentials = new NetworkCredential(userName, ToInsecureString(password));
                    
                    string filename=localFilePath.Split('\\').Last();
                    StringBuilder result = new StringBuilder();
                    FtpWebRequest requestDir = (FtpWebRequest)WebRequest.Create(address);
                    requestDir.Method = WebRequestMethods.Ftp.ListDirectory;
                    requestDir.Timeout = 3000;
                    requestDir.Credentials = new NetworkCredential(userName, ToInsecureString(password));

                    FtpWebResponse responseDir = (FtpWebResponse)requestDir.GetResponse();
                    StreamReader readerDir = new StreamReader(responseDir.GetResponseStream());

                    string line = readerDir.ReadLine();

                    while (line != null)
                    {
                        result.Append(line);
                        result.Append("\n");
                        line = readerDir.ReadLine();
                    }

                    var s= result.Remove(result.ToString().LastIndexOf('\n'), 1);
                    responseDir.Close();
                    if (result.ToString().Split('\n').Contains(ToInsecureString(pharmacySerial)) == true)
                    {
                        var uri = new Uri(address + "/" + ToInsecureString(pharmacySerial) + "/" + filename);
                        client.UploadFileAsync(uri, WebRequestMethods.Ftp.UploadFile, localFilePath);
                    }
                    else
                    {

                        requestDir = (FtpWebRequest)WebRequest.Create(address + "/" + ToInsecureString(pharmacySerial));

                        requestDir.Method = WebRequestMethods.Ftp.MakeDirectory;
                        requestDir.Credentials = new NetworkCredential(userName, ToInsecureString(password));
                        using (var resp = (FtpWebResponse)await requestDir.GetResponseAsync())
                        {

                            var statusCode = resp.StatusCode;
                            if (statusCode == FtpStatusCode.PathnameCreated)
                            {
                                var uri = new Uri(address + "/" + ToInsecureString(pharmacySerial) + "/" + filename);
                                client.UploadFileAsync(uri, WebRequestMethods.Ftp.UploadFile, localFilePath);

                            }
                            else
                            {
                                return statusCode.ToString();
                            }
                        }
                    }
                    return filename+"Copied to FTP successfuly.";
                }

            }
            catch (Exception ex)
            {
                return ex.Message;
            }

            //StringBuilder result = new StringBuilder();
            //FtpWebRequest requestDir = (FtpWebRequest)WebRequest.Create(address);
            //requestDir.Method = WebRequestMethods.Ftp.ListDirectory;
            //requestDir.Credentials = new NetworkCredential(user,password);

            //FtpWebResponse responseDir = (FtpWebResponse)requestDir.GetResponse();
            //StreamReader readerDir = new StreamReader(responseDir.GetResponseStream());

            //string line = readerDir.ReadLine();
            //while (line != null)
            //{
            //    result.Append(line);
            //    result.Append("\n");
            //    line = readerDir.ReadLine();
            //}

            //result.Remove(result.ToString().LastIndexOf('\n'), 1);
            //responseDir.Close();
            //if(result.ToString().Split('\n').Contains(folderName)==true)
            //{

            //}
        }
      
        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
        public static string MakeHash(string text)
        {
            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);
            var pbkdf2 = new Rfc2898DeriveBytes(text, salt, 10000);
            byte[] hash = pbkdf2.GetBytes(20);
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            string savedPasswordHash = Convert.ToBase64String(hashBytes);
            return savedPasswordHash;

        }
        public static bool VerifyHash(string password,string savedPasswordHash)
        {
            /* Fetch the stored value */
           // string savedPasswordHash = DBContext.GetUser(u => u.UserName == user).Password;
            /* Extract the bytes */
            byte[] hashBytes = Convert.FromBase64String(savedPasswordHash);
            /* Get the salt */
            byte[] salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);
            /* Compute the hash on the password the user entered */
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
            byte[] hash = pbkdf2.GetBytes(20);
            /* Compare the results */
            for (int i = 0; i < 20; i++)
                if (hashBytes[i + 16] != hash[i])
                    return false;
            return true;
        }
    }
}
