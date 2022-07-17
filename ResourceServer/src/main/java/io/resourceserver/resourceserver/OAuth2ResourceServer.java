package io.resourceserver.resourceserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServer {

    @Bean
    SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {

        http.authorizeRequests(
                (requests) -> requests.antMatchers("/photos").access("SCOPE_photo")
                        .anyRequest().authenticated());
        http.oauth2ResourceServer().jwt();
        return http.build();

    }
}
