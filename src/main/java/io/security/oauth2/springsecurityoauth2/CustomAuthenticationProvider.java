package io.security.oauth2.springsecurityoauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private OAuth2AuthorizationService oAuth2AuthorizationService;
    @Autowired
    private OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService;
    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        OAuth2AuthorizationCodeRequestAuthenticationProvider authenticationProvider
                = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, oAuth2AuthorizationService, oAuth2AuthorizationConsentService);
        OAuth2AuthorizationCodeRequestAuthenticationToken authenticate 
                = (OAuth2AuthorizationCodeRequestAuthenticationToken)authenticationProvider.authenticate(authorizationCodeRequestAuthentication);

        Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();

        return OAuth2AuthorizationCodeRequestAuthenticationToken.with(authenticate.getClientId(), principal)
                .authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
                .redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
                .scopes(authorizationCodeRequestAuthentication.getScopes())
                .state(authorizationCodeRequestAuthentication.getState() + UUID.randomUUID().toString())
                .authorizationCode(authorizationCodeRequestAuthentication.getAuthorizationCode())
                .build();

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
