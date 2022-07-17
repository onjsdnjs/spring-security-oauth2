package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServer {

    @Bean
    SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {

        http.authorizeRequests(
                (requests) -> requests.anyRequest().authenticated());
        http.oauth2ResourceServer().opaqueToken();
        return http.build();
    }

    /*@Bean
    public OpaqueTokenIntrospector nimbusOpaqueTokenIntrospector(OAuth2ResourceServerProperties properties) {
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = properties.getOpaquetoken();
        return new NimbusOpaqueTokenIntrospector(opaquetoken.getIntrospectionUri(),opaquetoken.getClientId(),opaquetoken.getClientSecret());
    }*/

    @Bean
    public OpaqueTokenIntrospector introspector() {
        return new CustomOpaqueTokenIntrospector();
    }
}
