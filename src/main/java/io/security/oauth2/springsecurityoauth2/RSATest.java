package io.security.oauth2.springsecurityoauth2;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSATest {

    public static void rsa(String message) throws Exception {

        KeyPair keyPair = RSAGen.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String encrypted = RSAGen.encrypt(message, publicKey);
        String decrypted = RSAGen.decrypt(encrypted, privateKey);

        System.out.println("message : " + message);
        System.out.println("decrypted : " + decrypted);

        byte[] bytePublicKey = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
        byte[] bytePrivateKey = privateKey.getEncoded();
        String base64PrivateKey = Base64.getEncoder().encodeToString(bytePrivateKey);

        PublicKey X509PublicKey = RSAGen.getPublicKeyFromKeySpec(base64PublicKey);
        String encrypted2 = RSAGen.encrypt(message, X509PublicKey);
        String decrypted2 = RSAGen.decrypt(encrypted2, privateKey);

        System.out.println("message : " + message);
        System.out.println("decrypted2 : " + decrypted2);

        PrivateKey PKCS8PrivateKey = RSAGen.getPrivateKeyFromKeySpec(base64PrivateKey);
        String decrypted3 = RSAGen.decrypt(encrypted2, PKCS8PrivateKey);

        System.out.println("message : " + message);
        System.out.println("decrypted3 : " + decrypted3);
    }
}