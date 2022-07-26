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

        byte[] bytePublicKey = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
        byte[] bytePrivateKey = privateKey.getEncoded();
        String base64PrivateKey = Base64.getEncoder().encodeToString(bytePrivateKey);

        PublicKey rePublicKey = RSAGen.getPublicKey(base64PublicKey);
        String encryptedRe = RSAGen.encrypt(message, rePublicKey);
        String decryptedRe = RSAGen.decrypt(encryptedRe, privateKey);

        // base64 암호화한 String 에서 Private Key 를 다시생성한후 복호화 테스트를 진행
        PrivateKey privateKeyRe = RSAGen.getPrivateKey(base64PrivateKey);
        String decryptedReRe = RSAGen.decrypt(encryptedRe, privateKeyRe);
    }
}
