package io.security.oauth2.springsecurityoauth2.init;

import io.security.oauth2.springsecurityoauth2.signature.RsaPublicKeySecuritySigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;

@Component
public class RsaKeyExtractor implements ApplicationRunner {

    @Autowired
    private RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner;

    @Autowired
    private OAuth2ResourceServerProperties properties;

    @Override
    public void run(ApplicationArguments args) throws Exception {

        String path = "E:\\project\\spring-security-oauth2\\src\\main\\resources\\certs\\";
        File file = new File(path+"publicKey.txt");

        if (!file.exists()) {

            FileInputStream is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, "pass1234".toCharArray());
            String alias = "apiKey";
            Key key = keystore.getKey(alias, "pass1234".toCharArray());
            if (key instanceof PrivateKey) {

                Certificate certificate = keystore.getCertificate(alias);
                PublicKey publicKey = certificate.getPublicKey();
                KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
                rsaPublicKeySecuritySigner.setPrivateKey(keyPair.getPrivate());

                String publicStr = java.util.Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
                publicStr = "-----BEGIN PUBLIC KEY-----\r\n" + publicStr + "\r\n-----END PUBLIC KEY-----";

                OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(path + "publicKey.txt"), Charset.defaultCharset());
                writer.write(publicStr);
                writer.close();
                is.close();
            }
        }
    }
}
