using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Services;

namespace VStackAuthenURLSapmle
{
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    public class AuthenURL : System.Web.Services.WebService
    {
        public const string PRIVATE_KEY_START_LINE = "-----BEGIN PRIVATE KEY-----\n";
        public const string PRIVATE_KEY_END_LINE = "\n-----END PRIVATE KEY-----";

        [WebMethod]
        public void test()
        {
            //Important: change $secretCode, $privateKey value (go to: https://developer-vstack.vht.com.vn, choose your app, click menu: Keys)
            string secretCode = "c21d5ecff0c1eece";
            string privateKeyStr = @"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDneiwUO0atULRN
cnjEsETbT+mao49gmntn3ysw1G2K31L1EOAVT/yxy45j7GaY1rHloQnM7ESGrfUe
dHhitR/LgtaTaGCS2An774IHWYyQu6FT8wU1musyd2LtbOFhaSE+fbprmd6cQeg3
eQtuzXmJIvJEcshc+XZbVdoW0/iBifEmoRBbv6VY0sPszPnR1McHIaAoBjVUoFVg
qPn8AHzoMN8dG4n+Evzh9wgHjn6++dI/NRJIBi/QBe8HkOQ5/Js9gy4akWegyKRw
1ew7bIX+QZ1UvzZDodn1EyMjFZqYmuhYXxlV3jxxor8tTCBSohLhKy+fOWR1xOeG
e3tHJke/AgMBAAECggEAa0N445MoSC3qryzJe9N2xO3+ATOjwA81+kc2+3SkokKk
bX15aUbcgQMjo3grfs2WOCNsqDIf+wznVkqAcrUd269wgXRPtBw6XC17Yq6DbZoU
wxMNKe706DjcdcsLkZkm149pcG0n896yneoQezLqC7tO6psJ79OFngNlgUiOkm+Y
vlhItLo+dDVwKt+TfQlbsIWNHWO/RH/WtpcopnUkFwJmzgNUyLYfhsG4Yyh2m6Fu
eeoWzZ0Gt99Jyw1E0d3BbnMplqN53xOWNijsMj8lpXGMwtGeIx4nY2xYjgMrmAcY
j+Tw5pt/tTuqNK9gYeAG8cN6C+FgJq1d3vv/MII/sQKBgQD7hJT4WNxkC3ulv0/O
6DSfwltnZOf+Py7h7DBpLPBNCTunAgl1lvN05FnBlkZGBYqWomgJr8/14GfYw55s
sCijc8D/yWW/xZ2MzZvcePEx9Ctfwee7KGSpqIIWjfSoYpsFgms7qxJX8w7x7amk
NV90CxhsZVMu+5uQxem4bwduxwKBgQDrmipQS8Mv6pZ/SwUo/Egdz8TM2KgtfR5X
X0enoZH3Grp3UPGANZDocZiHLuiHueonMWcFNVeHcGWv4EQZyod1Ol19CxGr1IwU
2XqYkCMSHVSCNGazc9C4WUffHlCrcT7o2sdO+VC1Gu+OBfRCoWISr8hDUfILOjON
DZVxgr3HSQKBgBBx6b+XJ8nOymXa7V/s5MvxTEKlYVnJTcptw/iMfKW8zc6snmu2
0/I3n/q9VZjscdRJiB3iBengo0mT+L7Igc+2GM9gnqt8Q0Hai69NpQ+MFG3tYrZk
/LfvEZph67Y6xEIG9fXvyIJBnR+KV4YqCzSuKQmlUlwHDXPYzOBHOigvAoGAFCc9
01yHt8OTWBQsvtLFwHcTWIp36Fw5ijPGR1qUx9RreuVboyHx4VBGQdoLXgDTPMMH
EvT7JcTBjgfbC3G9oJN7h8S4oEAwM2BfEknSFiyYHAMrfdI8WmiYs0c+k0u+m+CL
CABfnP5O25E60bBIWVzb/pY15Cv4WOp+jBUo8rECgYBCztjjlMX6wdH2aScI5VoB
1yf+GHUDB7wvNxjvGEmtazI8gcRoeKXZM+nu0OPV1eCrVQavRXjxLtZ2LQ/ZBq7+
4tjzC5eewoDr2HM7C/+o9S2P/zOtcFKJt3+mrWhh+h2BeEkT7mr3bnLlI4DtTFjs
IoIt4q2hgSWIvmnrtcgcbA==";



            string token = HttpContext.Current.Request["token"];//POST type: application/x-www-form-urlencoded
            var bytesToDecrypt = Convert.FromBase64String(token);

            privateKeyStr = PRIVATE_KEY_START_LINE + privateKeyStr + PRIVATE_KEY_END_LINE;

            string plaintextToken = DecryptToken(bytesToDecrypt, privateKeyStr);
            int result = 1;

            if (plaintextToken.Length > 0)
            {
                JObject plaintextJson = JObject.Parse(plaintextToken);
                if (plaintextJson != null)
                {
                    string appId = (string)plaintextJson["appId"];
                    string VStackUserID = (string)plaintextJson["VStackUserID"];
                    long timestamp = (long)plaintextJson["timestamp"];
                    string code = (string)plaintextJson["code"];
                    string userCredentials = (string)plaintextJson["userCredentials"];

                    //verify code = md5(appId . "_" . timestamp . "_" . secretCode)
                    //		to make sure request is from VStack
                    string code2 = GetMD5Hash(appId + "_" + timestamp + "_" + secretCode);

                    if (code2.Equals(code))
                    {
                        //check user credentials
                        bool userCredentialsValid = true; //you can validate VStackUserID and $userCredentials in your Database, etc

                        if (userCredentialsValid)
                        {
                            result = 0;
                        }
                    }
                }

                JObject jsonRes = new JObject();
                jsonRes["result"] = result;

                HttpContext.Current.Response.Write(jsonRes.ToString());
            }
        }

        private static string DecryptToken(byte[] bytesToDecrypt, string privateKeyStr)
        {
            TextReader sr = new StringReader(privateKeyStr);
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)new PemReader(sr).ReadObject();
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());
            decryptEngine.Init(false, privateKey);
            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));

            return decrypted;
        }

        public static String GetMD5Hash(String TextToHash)
        {
          //Check wether data was passed
          if((TextToHash == null) || (TextToHash.Length == 0))
          {
            return String.Empty;
          }

          //Calculate MD5 hash. This requires that the string is splitted into a byte[].
          MD5 md5 = new MD5CryptoServiceProvider();
          byte[] textToHash = Encoding.Default.GetBytes(TextToHash);
          byte[] result = md5.ComputeHash(textToHash);

          //Convert result back to string.
          return System.BitConverter.ToString(result).Replace("-", "").ToLower() ; 
        }
    }
}
