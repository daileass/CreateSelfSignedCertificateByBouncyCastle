

namespace CreateSelfSignedCertificateByBouncyCastle
{
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Utilities;
    using Org.BouncyCastle.Utilities.Encoders;
    using Org.BouncyCastle.X509;
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    class Program
    {
        static void Main(string[] args)
        {
            /*
                前言：最近有个需求是需要对文档进行签名，考虑到数字签名证书问题，所以生成一个自签名的数字证书；
                描述：本示例基于BouncyCastle.Crypto组件提供的算法生成证书，
                        演示了生成了cer证书、pfx证书及加载pfx证书对字符串加密解密
                
            */

            var takeEffect = DateTime.Now;  // 生效时间
            var loseEffect = DateTime.Now.AddYears(2);  // 失效时间
            var password = "ABCD123456";    //证书密码
            var signatureAlgorithm = "SHA256WITHRSA";  //签名算法
            var friendlyName = $"{Guid.NewGuid().ToString("N")}dpps.fun"; // 别名

            // 获取颁发者DN
            X509Name issuer = GetIssuer();

            // 获取使用者DN
            X509Name subject = GetSubject();

            // 证书存放目录
            string file = System.Environment.CurrentDirectory + "\\Cert\\";
            if (!Directory.Exists(file))
            {
                Directory.CreateDirectory(file);
            }
            string pfxPath = $"{file}{friendlyName}.pfx";
            string certPath = $"{file}{friendlyName}.cer";

            // 生成证书
            GenerateCertificate(certPath, pfxPath, password, signatureAlgorithm, issuer, subject, takeEffect, loseEffect, friendlyName);

            // 加载PFX证书
            LoadingPfxCertificate(pfxPath, password);

            Console.WriteLine("OK");
            Console.ReadLine();
        }

        /// <summary>
        /// 获取使用者DN.
        /// </summary>
        /// <returns>使用者DN.</returns>
        private static X509Name GetSubject()
        {
            // 使用者DN
            return new X509Name(
                new ArrayList
                {
                    X509Name.C,
                    X509Name.O,
                    X509Name.CN
                },
                new Hashtable
                {
                    [X509Name.C] = "CN",
                    [X509Name.O] = "ICH",
                    [X509Name.CN] = "*.dpps.fun"
                }
            );
        }

        /// <summary>
        /// 获取颁发者DN.
        /// </summary>
        /// <returns>颁发者DN.</returns>
        private static X509Name GetIssuer()
        {
            // 颁发者DN
            return new X509Name(
                new ArrayList
                {
                    X509Name.C,
                    X509Name.O,
                    X509Name.OU,
                    X509Name.L,
                    X509Name.ST,
                    X509Name.E,
                },
                new Hashtable
                {
                    [X509Name.C] = "CN",// 证书的语言
                    [X509Name.O] = "dpps.fun",//设置证书的办法者
                    [X509Name.OU] = "dpps.fun Fulu RSA CA 2020",
                    [X509Name.L] = "dpps",
                    [X509Name.ST] = "dpps",
                    [X509Name.E] = "472067093@qq.com",
                }
            );
        }


        /// <summary>
        /// 生成证书
        /// </summary>
        /// <param name="certPath">certPath（只含公钥）</param>
        /// <param name="pfxPath">pfxPath（含公私钥）</param>
        /// <param name="password">证书密码</param>
        /// <param name="signatureAlgorithm">设置将用于签署此证书的签名算法</param>
        /// <param name="issuer">设置此证书颁发者的DN</param>
        /// <param name="subject">设置此证书使用者的DN</param>
        /// <param name="takeEffect">证书生效时间</param>
        /// <param name="loseEffect">证书失效时间</param>
        /// <param name="friendlyName">设置证书友好名称（可选）</param>
        /// <param name="keyStrength">密钥长度</param>
        public static void GenerateCertificate(
            string certPath,
            string pfxPath,
            string password,
            string signatureAlgorithm,
            X509Name issuer,
            X509Name subject,
            DateTime takeEffect,
            DateTime loseEffect,
            string friendlyName,
            int keyStrength = 2048)
        {
            SecureRandom random = new SecureRandom(new CryptoApiRandomGenerator());
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator(); //RSA密钥对生成器
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, subjectKeyPair.Private, random);
            //the certificate generator

            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public);

            //允许作为一个CA证书（可以颁发下级证书或进行签名）
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));

            //使用者密钥标识符
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(spki));

            //授权密钥标识符
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(spki));

            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, true, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            //证书序列号
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

            certificateGenerator.SetSerialNumber(serialNumber);

            certificateGenerator.SetIssuerDN(issuer);   //颁发者信息

            certificateGenerator.SetSubjectDN(subject); //使用者信息

            certificateGenerator.SetNotBefore(takeEffect); //证书生效时间

            certificateGenerator.SetNotAfter(loseEffect); //证书失效时间

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(signatureFactory);

            //生成cer证书，公钥证
            var certificate2 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate))
            {
                FriendlyName = friendlyName, //设置友好名称
            };
            // cer公钥文件
            var bytes = certificate2.Export(X509ContentType.Cert);
            using (var fs = new FileStream(certPath, FileMode.Create))
            {
                fs.Write(bytes, 0, bytes.Length);
            }

            //另一种代码生成p12证书的方式（要求使用.net standard 2.1）
            //certificate2 = certificate2.CopyWithPrivateKey(DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private));
            //var bytes2 = certificate2.Export(X509ContentType.Pfx, password);
            //using (var fs = new FileStream(pfxPath, FileMode.Create))
            //{
            //    fs.Write(bytes2, 0, bytes2.Length);
            //}

            // 生成pfx证书，公私钥证
            var certEntry = new X509CertificateEntry(certificate);
            var store = new Pkcs12StoreBuilder().Build();
            store.SetCertificateEntry(friendlyName, certEntry);   //设置证书
            var chain = new X509CertificateEntry[1];
            chain[0] = certEntry;
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), chain);   //设置私钥
            using (var fs = File.Create(pfxPath))
            {
                store.Save(fs, password.ToCharArray(), random); //保存
            };
        }

        /// <summary>
        /// 加载证书
        /// </summary>
        /// <param name="pfxPath"></param>
        /// <param name="password"></param>
        private static void LoadingPfxCertificate(string pfxPath, string password)
        {
            //加载证书
            X509Certificate2 pfx = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);
            var keyPair = DotNetUtilities.GetKeyPair(pfx.PrivateKey);
            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var privateKey = Base64.ToBase64String(privateKeyInfo.ParsePrivateKey().GetEncoded());
            var publicKey = Base64.ToBase64String(subjectPublicKeyInfo.GetEncoded());
            Console.ForegroundColor = ConsoleColor.DarkYellow;

            Console.WriteLine("Pfx证书私钥：");
            Console.WriteLine(privateKey);
            Console.WriteLine("Pfx证书公钥：");
            Console.WriteLine(publicKey);

            var beEncryptedData = "hello rsa";
            Console.WriteLine($"加密原文：{beEncryptedData}");
            var cipherText = RSAHelper.Encrypt(beEncryptedData, publicKey);
            Console.WriteLine("加密结果：");
            Console.WriteLine(cipherText);

            var datares = RSAHelper.Decrypt(cipherText, privateKey);
            Console.WriteLine($"解密结果：{datares}");
        }
    }
}
