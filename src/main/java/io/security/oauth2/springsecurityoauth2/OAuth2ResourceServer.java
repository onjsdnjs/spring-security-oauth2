package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServer {

    @Bean
    SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
        http.antMatcher("/photos/1").authorizeRequests(
                (requests) -> requests.antMatchers(HttpMethod.GET, "/photos/1")
                .hasAuthority("SCOPE_photo")
                .anyRequest().authenticated());
        http.oauth2ResourceServer().jwt();
        return http.build();
    }

    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http.antMatcher("/photos/2").authorizeRequests(
                (requests) -> requests.antMatchers(HttpMethod.GET, "/photos/2").permitAll());
        http.oauth2ResourceServer().jwt();
        return http.build();
    }
}
