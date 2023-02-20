# MatterCABuild
build ca by aws pca

###基于aws pcm构建符合matter协议标准的PAA，PAI，DAC
注意，本代码来自于aws文档：
https://docs.aws.amazon.com/privateca/latest/userguide/API-CBR-intro.html
部分进行了修改，使用前建议如下：
1. 本地配置aws credentials文件，windows操作系统中，一般位于：C:\Users\name\.aws\credentials；
Linux操作系统中，位于～/.aws/credentials, 方便起见，建议使用aws命令行工具，用aws configure命令自动生成；
   aws cli安装文档：https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html；
   注意，配置时，使用的访问密钥皆来自于IAM User
2. ProductAttestationAuthorityActivation类，用于生成PAA，有以下注意项:  
   __a)__ 代码中只设置了Subject的CN（CommonName）属性，若需要同时添加VID等信息，可以修改代码第47行-54行，改为以下：  
   ```
   // Define custom attributes
   List<CustomAttribute> customAttributes = Arrays.asList(
   //2.5.4.3 代表CN
       new CustomAttribute()
           .withObjectIdentifier("2.5.4.3")
           .withValue("Matter Test PAA"),
   //1.3.6.1.4.1.37244.2.1 的值为CSA提供的VID
       new CustomAttribute()
           .withObjectIdentifier("1.3.6.1.4.1.37244.2.1")
           .withValue("FFF1")
   );

    // Define a CA subject.
    ASN1Subject subject = new ASN1Subject();
    subject.setCustomAttributes(customAttributes);
   ```
   __b)__ 参数 **endpointRegion** 注意修改为需要使用的aws region  


3. ProductAttestationIntermediateActivation类用于生成PAI，有以下注意点：  
   __a)__ 参数paaArn需要替换为我们生成的PAA的arn，可以在aws pca console中对应ca的详情中寻找，也可以看
   ProductAttestationAuthorityActivation类执行时的输出；  
   __b)__ 同理，我们需要替换region参数；  
   __c)__ 代码83行指定的1.3.6.1.4.1.37244.2.1，为VID，生产需要自行替换84行的值，VID由CSA提供;  
   __d)__ 代码84行指定的1.3.6.1.4.1.37244.2.1，为PID，生产需要自行替换87行的值;
   
4. IssueDeviceAttestationCertificate类用于发布DAC， 使用前，先使用openssl生成csr文件和证书密钥key文件，参考命令如下：
```
openssl ecparam -out elsenow-ecc.key -name prime256v1 -genkey
openssl req -nodes -new -key elsenow-ecc.key \
-out matter-registration.csr \
cat iot-registration.csr
```

记录下cat matter-registration.csr输出的结果，并替换IssueDeviceAttestationCertificate类中代码第94行的strCSR参数的值；

替换代码76行region参数，endpointRegion
替换代码91行PAI的ARN，PAI ARN在生成时会打印，也可以在ACM PCA控制台查询；
执行代码后，会打印DAC的arn；

* 等待证书发布完成：
```
aws acm-pca wait certificate-issued \
--certificate-authority-arn [替换为您自己的PAI ARN] \
--certificate-arn [替换为您自己的证书 ARN]
```
* 获取证书内容：
```
aws acm-pca get-certificate \
--certificate-authority-arn [替换为您自己的PAI ARN] \
--certificate-arn [替换为您自己的证书 ARN]
```

