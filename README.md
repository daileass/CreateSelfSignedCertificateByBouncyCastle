# CreateSelfSignedCertificateByBouncyCastle
前言：最近有个需求是需要对文档进行签名，考虑到数字签名证书问题，所以生成一个自签名的数字证书；                 
描述：本示例基于BouncyCastle.Crypto组件提供的算法生成证书，演示了生成了cer证书、pfx证书及加载pfx证书对字符串加密解密
部分代码展示：


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
