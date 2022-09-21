package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.springsecurityoauth2.JWKTest.jwk;

@SpringBootApplication
public class SpringSecurityOauth2Application {
    public static void main(String[] args) throws Exception {
        jwk();
//        SpringApplication.run(SpringSecurityOauth2Application.class, args);
    }
}
