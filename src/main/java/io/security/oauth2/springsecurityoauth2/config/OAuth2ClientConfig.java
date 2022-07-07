package io.security.oauth2.springsecurityoauth2.config;

import io.security.oauth2.springsecurityoauth2.filter.CustomOAuth2LoginAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Autowired
    private DefaultOAuth2AuthorizedClientManager authorizedClientManager;
    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.antMatchers("/","/oauth2Login","/logout").permitAll().anyRequest().authenticated());
        http
//                .oauth2Login().and()
                .oauth2Client()
                .and()
                .addFilterBefore(customOAuth2LoginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                ;
        return http.build();
    }
    public CustomOAuth2LoginAuthenticationFilter customOAuth2LoginAuthenticationFilter() throws Exception {
        CustomOAuth2LoginAuthenticationFilter customOAuth2LoginAuthenticationFilter =
                new CustomOAuth2LoginAuthenticationFilter(authorizedClientManager,authorizedClientRepository);
        customOAuth2LoginAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/home");
        });
        return customOAuth2LoginAuthenticationFilter;
    }
}
