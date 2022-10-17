package io.security.oauth2.authorizatonserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        authorizationServerConfigurer.authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                .authenticationProvider(customAuthenticationProvider)
                                .authorizationResponseHandler(new AuthenticationSuccessHandler() {
                                            @Override
                                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                                OAuth2AuthorizationCodeRequestAuthenticationToken authentication1 = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
                                                System.out.println(authentication);
                                                String redirectUri = authentication1.getRedirectUri();
                                                String authorizationCode = authentication1.getAuthorizationCode().getTokenValue();
                                                String state = null;
                                                if (StringUtils.hasText(authentication1.getState())) {
                                                    state = authentication1.getState();
                                                }
                                                response.sendRedirect(redirectUri+"?code="+authorizationCode+"&state="+state);
                                            }
                                        }
                                )
                                .errorResponseHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        System.out.println(exception.toString());
                                        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                                    }
                                })
                );

        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
        http
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );
        return http.build();
    }
}

