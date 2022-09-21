package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.springsecurityoauth2.MacTest.hmac;
import static io.security.oauth2.springsecurityoauth2.RSATest.rsa;

@SpringBootApplication
public class SpringSecurityOauth2Application {
    public static void main(String[] args) throws Exception {
//        messageDigest("Spring Security");
//        signature("Spring Security");
        hmac("Spring Security");
        rsa("Spring Security");
//        SpringApplication.run(SpringSecurityOauth2Application.class, args);
    }
}
