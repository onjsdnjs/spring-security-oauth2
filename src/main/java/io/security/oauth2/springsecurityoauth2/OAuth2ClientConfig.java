package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated());
        http
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .loginProcessingUrl("/login/v1/oauth2/code/*")
                        .authorizationEndpoint(authorizationEndpointConfig ->
                                authorizationEndpointConfig.baseUri("/oauth2/v1/authorization"))
                        .redirectionEndpoint(redirectionEndpointConfig ->
                                redirectionEndpointConfig.baseUri("/login/v1/oauth2/code/*"))
                )
        ;

        return http.build();
    }
}
