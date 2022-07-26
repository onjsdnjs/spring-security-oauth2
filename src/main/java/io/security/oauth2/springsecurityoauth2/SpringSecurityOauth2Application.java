package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.springsecurityoauth2.MessageDigestTest.*;
import static io.security.oauth2.springsecurityoauth2.SignatureTest.signature;

@SpringBootApplication
public class SpringSecurityOauth2Application {
    public static void main(String[] args) throws Exception {

//        messageDigest("스프링 시큐리티");
        signature("스프링 시큐리티");

    }
}
