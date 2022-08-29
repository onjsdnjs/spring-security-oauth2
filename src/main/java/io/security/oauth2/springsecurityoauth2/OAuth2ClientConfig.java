package io.security.oauth2.springsecurityoauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests((requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated());
        http.authorizeRequests((requests) -> requests
                .antMatchers("/home")
                .permitAll()
                .anyRequest().authenticated());
        http.oauth2Login(oauth2Login -> oauth2Login.authorizationEndpoint(authEndpoint -> authEndpoint.authorizationRequestResolver(customResolver())));
//        http.oauth2Login(oauth2 -> oauth2.loginPage("/login"));
        return http.build();
   }

    private OAuth2AuthorizationRequestResolver customResolver() {
        return new CustomResolver(clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }
}
