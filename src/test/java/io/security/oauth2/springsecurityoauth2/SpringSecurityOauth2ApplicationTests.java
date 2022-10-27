package io.security.oauth2.springsecurityoauth2;

import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringSecurityOauth2ApplicationTests {

    @Autowired
    private UserRepository repository;

    @Test
    void contextLoads() {
    }
}
