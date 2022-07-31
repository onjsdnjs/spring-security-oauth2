package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.springsecurityoauth2.MacTest.hmac;
import static io.security.oauth2.springsecurityoauth2.MessageDigestTest.*;
import static io.security.oauth2.springsecurityoauth2.RSATest.rsa;
import static io.security.oauth2.springsecurityoauth2.SignatureTest.signature;

@SpringBootApplication
public class SpringSecurityOauth2Application {
    public static void main(String[] args) throws Exception {

//        messageDigest("Spring Security");
        hmac("Spring Security");
//        signature("Spring Security");
//        rsa("Spring Security");

    }
}
