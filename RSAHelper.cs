using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CreateSelfSignedCertificateByBouncyCastle
{
    public class RSAHelper
    {
        #region 使用私钥签名Sign(string data, string privateKey, RSAType rsaType, Encoding encoding)
        /// <summary>
        /// 使用私钥签名
        /// </summary>
        /// <param name="data">待签名串</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encoding">编码类型，推荐使用UTF8</param>
        /// <param name="rsaType">签名类型，默认RSA2</param>
        /// <returns></returns>
        public static string Sign(string data, string privateKey, Encoding encoding, RSAType rsaType = RSAType.RSA2)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            RSA _privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
            HashAlgorithmName _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
            var signatureBytes = _privateKeyRsaProvider.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }
        /// <summary>
        /// 使用私钥签名，默认Encoding为Encoding.UTF8
        /// </summary>
        /// <param name="data">待签名串</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="rsaType">签名类型，默认RSA2</param>
        /// <returns></returns>
        public static string Sign(string data, string privateKey, RSAType rsaType = RSAType.RSA2)
        {
            return Sign(data, privateKey, Encoding.UTF8, rsaType);
        }
        /// <summary>
        /// 使用私钥签名
        /// </summary>
        /// <param name="parameters">待签参数</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encoding">编码类型，推荐使用UTF8</param>
        /// <param name="rsaType">签名类型，默认RSA2</param>
        /// <param name="removeSign">是否移除签名串，默认移除名为“sign”的签名串</param>
        /// <returns></returns>
        public static string SignParameters(IDictionary<string, string> parameters, string privateKey, Encoding encoding, RSAType rsaType = RSAType.RSA2, bool removeSign = true)
        {

            string data = GetSignContent(parameters, removeSign);
            byte[] dataBytes = encoding.GetBytes(data);
            RSA _privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
            HashAlgorithmName _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
            var signatureBytes = _privateKeyRsaProvider.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }
        /// <summary>
        /// 使用私钥签名，默认Encoding为Encoding.UTF8
        /// </summary>
        /// <param name="parameters">待签参数</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="rsaType">签名类型，默认RSA2</param>
        /// <param name="removeSign">是否移除签名串，默认移除名为“sign”的签名串</param>
        /// <returns></returns>
        public static string SignParameters(IDictionary<string, string> parameters, string privateKey, RSAType rsaType = RSAType.RSA2, bool removeSign = true)
        {
            return SignParameters(parameters, privateKey, Encoding.UTF8, rsaType, removeSign);
        }
        #endregion

        #region 使用公钥验证签名Verify(string data, string sign,string publickey,RSAType rsaType,Encoding encoding)
        /// <summary>
        /// 使用公钥验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="sign">签名串</param>
        /// <param name="publickey">公钥</param>
        /// <param name="encoding">编码类型，推荐使用UTF8</param>
        /// <param name="rsaType">签名类型，推默认RSA2</param>
        /// <returns></returns>
        public static bool Verify(string data, string sign, string publickey, Encoding encoding, RSAType rsaType = RSAType.RSA2)
        {
            byte[] dataBytes = encoding.GetBytes(data);
            byte[] signBytes = Convert.FromBase64String(sign);
            RSA _publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publickey);
            HashAlgorithmName _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
            var verify = _publicKeyRsaProvider.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return verify;
        }
        /// <summary>
        /// 使用公钥验证签名 默认Encoding为Encoding.UTF8
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="sign">签名串</param>
        /// <param name="publickey">公钥</param>
        /// <param name="rsaType">签名类型，推默认RSA2</param>
        /// <returns></returns>
        public static bool Verify(string data, string sign, string publickey, RSAType rsaType = RSAType.RSA2)
        {
            return Verify(data, sign, publickey, Encoding.UTF8, rsaType);
        }
        /// <summary>
        /// 使用公钥验证签名
        /// </summary>
        /// <param name="parameters">代验签参数</param>
        /// <param name="publickey">公钥</param>
        /// <param name="encoding">编码类型，推荐使用UTF8</param>
        /// <param name="rsaType">签名类型，推荐使用RSA2</param>
        /// <param name="removeSign">是否移除签名串，默认移除名为“sign”的签名串</param>
        /// <returns></returns>
        public static bool VerifyParameters(IDictionary<string, string> parameters, string publickey, Encoding encoding, RSAType rsaType = RSAType.RSA2, bool removeSign = true)
        {
            string sign = parameters["sign"];
            parameters.Remove("sign");

            byte[] dataBytes = encoding.GetBytes(GetSignContent(parameters, removeSign));
            byte[] signBytes = Convert.FromBase64String(sign);
            RSA _publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publickey);
            HashAlgorithmName _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
            var verify = _publicKeyRsaProvider.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return verify;
        }
        /// <summary>
        /// 使用公钥验证签名 默认Encoding为Encoding.UTF8
        /// </summary>
        /// <param name="parameters">代验签参数</param>
        /// <param name="publickey">公钥</param>
        /// <param name="rsaType">签名类型，推荐使用RSA2</param>
        /// <param name="removeSign">是否移除签名串，默认移除名为“sign”的签名串</param>
        /// <returns></returns>
        public static bool VerifyParameters(IDictionary<string, string> parameters, string publickey, RSAType rsaType = RSAType.RSA2, bool removeSign = true)
        {
            return VerifyParameters(parameters, publickey, Encoding.UTF8, rsaType, removeSign);
        }
        #endregion

        #region 获取/组装待签名串GetSignContent(IDictionary<string, string> parameters, bool removeSign = true)
        /// <summary>
        /// 获取/组装待签名串
        /// </summary>
        /// <param name="parameters">参数内容</param>
        /// <param name="removeSign">是否移除签名串，默认移除名为“sign”的签名串</param>
        /// <returns></returns>
        public static string GetSignContent(IDictionary<string, string> parameters, bool removeSign = true)
        {
            if (removeSign && parameters.ContainsKey("sign"))
            {
                parameters.Remove("sign");
            }
            // 第一步：把字典按Key的字母顺序排序
            IDictionary<string, string> sortedParams = new SortedDictionary<string, string>(parameters);
            IEnumerator<KeyValuePair<string, string>> dem = sortedParams.GetEnumerator();

            // 第二步：把所有参数名和参数值串在一起
            StringBuilder query = new StringBuilder("");
            while (dem.MoveNext())
            {
                string key = dem.Current.Key;
                string value = dem.Current.Value;
                if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value)) // 空字段不加入签名/验签
                {
                    query.Append(key).Append("=").Append(value).Append("&");
                }
            }
            string content = query.ToString().Substring(0, query.Length - 1);

            return content;
        }
        #endregion

        #region 解密Decrypt(string cipherText,string privateKey)
        /// <summary>
        /// 解密(无限长度)
        /// </summary>
        /// <param name="cipherText">加密串</param>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public static string Decrypt(string cipherText, string privateKey)
        {
            RSA _privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
            if (_privateKeyRsaProvider == null)
            {
                throw new Exception("_privateKeyRsaProvider is null");
            }
            var inputBytes = Convert.FromBase64String(cipherText);
            int bufferSize = _privateKeyRsaProvider.KeySize / 8;
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                 outputStream = new MemoryStream())
            {
                while (true)
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var rawBytes = _privateKeyRsaProvider.Decrypt(temp, RSAEncryptionPadding.Pkcs1);
                    outputStream.Write(rawBytes, 0, rawBytes.Length);
                }
                return Encoding.UTF8.GetString(outputStream.ToArray());
            }

            //return Encoding.UTF8.GetString(_privateKeyRsaProvider.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1));
        }
        /// <summary>
        /// 分段解密
        /// </summary>
        /// <param name="encryptedInput"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        private string RsaDecrypt(string encryptedInput, string privateKey)
        {
            if (string.IsNullOrEmpty(encryptedInput))
            {
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(privateKey))
            {
                throw new ArgumentException("Invalid Private Key");
            }

            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var inputBytes = Convert.FromBase64String(encryptedInput);
                rsaProvider.FromXmlString(privateKey);
                int bufferSize = rsaProvider.KeySize / 8;
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(inputBytes),
                     outputStream = new MemoryStream())
                {
                    while (true)
                    {
                        int readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                        {
                            break;
                        }

                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var rawBytes = rsaProvider.Decrypt(temp, false);
                        outputStream.Write(rawBytes, 0, rawBytes.Length);
                    }
                    return Encoding.UTF8.GetString(outputStream.ToArray());
                }
            }
        }
        #endregion

        #region 加密 Encrypt(string text,string publickey)
        /// <summary>
        /// 加密(无限长度)
        /// </summary>
        /// <param name="text">待加密串</param>
        /// <param name="publickey">公钥</param>
        /// <returns></returns>
        public static string Encrypt(string text, string publickey)
        {
            RSA _publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publickey);
            if (_publicKeyRsaProvider == null)
            {
                throw new Exception("_publicKeyRsaProvider is null");
            }
            var inputBytes = Encoding.UTF8.GetBytes(text);
            int bufferSize = (_publicKeyRsaProvider.KeySize / 8) - 11;//单块最大长度
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                 outputStream = new MemoryStream())
            {
                while (true)
                { //分段加密
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var encryptedBytes = _publicKeyRsaProvider.Encrypt(temp, RSAEncryptionPadding.Pkcs1);
                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }
                return Convert.ToBase64String(outputStream.ToArray());//转化为字节流方便传输
            }
        }
        /// <summary>
        /// 分段加密
        /// </summary>
        /// <param name="rawInput"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        private string RsaEncrypt(string rawInput, string publicKey)
        {
            if (string.IsNullOrEmpty(rawInput))
            {
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(publicKey))
            {
                throw new ArgumentException("Invalid Public Key");
            }

            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var inputBytes = Encoding.UTF8.GetBytes(rawInput);//有含义的字符串转化为字节流
                rsaProvider.FromXmlString(publicKey);//载入公钥
                int bufferSize = (rsaProvider.KeySize / 8) - 11;//单块最大长度
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(inputBytes),
                     outputStream = new MemoryStream())
                {
                    while (true)
                    { //分段加密
                        int readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                        {
                            break;
                        }

                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var encryptedBytes = rsaProvider.Encrypt(temp, false);
                        outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    return Convert.ToBase64String(outputStream.ToArray());//转化为字节流方便传输
                }
            }
        }
        #endregion

        #region 私有方法
        /// <summary>
        /// 使用私钥创建RSA实例
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        private static RSA CreateRsaProviderFromPrivateKey(string privateKey)
        {
            var privateKeyBits = Convert.FromBase64String(privateKey);

            var rsa = RSA.Create();
            var rsaParameters = new RSAParameters();

            using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = 0;
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)
                    binr.ReadByte();
                else if (twobytes == 0x8230)
                    binr.ReadInt16();
                else
                    throw new Exception("Unexpected value read binr.ReadUInt16()");

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102)
                    throw new Exception("Unexpected version");

                bt = binr.ReadByte();
                if (bt != 0x00)
                    throw new Exception("Unexpected value read binr.ReadByte()");

                rsaParameters.Modulus = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.Exponent = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.D = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.P = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.Q = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.DP = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.DQ = binr.ReadBytes(GetIntegerSize(binr));
                rsaParameters.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
            }

            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        /// <summary>
        /// 使用公钥创建RSA实例
        /// </summary>
        /// <param name="publicKeyString">公钥</param>
        /// <returns></returns>
        private static RSA CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            var x509Key = Convert.FromBase64String(publicKeyString);

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream mem = new MemoryStream(x509Key))
            {
                using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                    if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    var rsa = RSA.Create();
                    RSAParameters rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsa.ImportParameters(rsaKeyInfo);

                    return rsa;
                }

            }
        }

        /// <summary>
        /// 导入密钥算法
        /// </summary>
        /// <param name="binr">BinaryReader</param>
        /// <returns></returns>
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();
            else
            if (bt == 0x82)
            {
                var highbyte = binr.ReadByte();
                var lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }

        #endregion
    }

    public enum RSAType
    {
        /// <summary>
        /// SHA1
        /// </summary>
        RSA = 0,
        /// <summary>
        /// RSA2 密钥长度至少为2048
        /// SHA256
        /// </summary>
        RSA2
    }
}
