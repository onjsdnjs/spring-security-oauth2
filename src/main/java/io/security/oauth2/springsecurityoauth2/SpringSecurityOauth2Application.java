package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.springsecurityoauth2.MessageDigestTest.createMD5;
import static io.security.oauth2.springsecurityoauth2.MessageDigestTest.validateMD5;

@SpringBootApplication
public class SpringSecurityOauth2Application {
    public static void main(String[] args) throws Exception {

        // MessageDigest
        createMD5("스프링 시큐리티");
        validateMD5("스프링 시큐리티");

    }
}
