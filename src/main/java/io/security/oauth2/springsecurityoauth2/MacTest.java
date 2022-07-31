package io.security.oauth2.springsecurityoauth2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MacTest {

    public static String hmac(String data) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        String secret = "hmacKey";
        String algorithms = "HmacSHA256";

        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes("utf-8"), algorithms);

        Mac mac = Mac.getInstance(algorithms);

        mac.init(secretKey);

        byte[] hash = mac.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(hash);
    }
}
