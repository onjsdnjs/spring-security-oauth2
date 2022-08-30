/*
package io.security.oauth2.springsecurityoauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class IndexController2 {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    public OAuth2User user(Authentication authentication, HttpServletRequest request) {

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        String registrationId = authToken.getAuthorizedClientRegistrationId();
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

        OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientRepository.loadAuthorizedClient(registrationId, authentication, request);

        OAuth2AccessToken auth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, oAuth2AuthorizedClient.getAccessToken().getTokenValue(), Instant.MIN, Instant.MAX);
        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, auth2AccessToken);

        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();

        OAuth2User user = defaultOAuth2UserService.loadUser(oAuth2UserRequest);

        return user;
    }

    @GetMapping("/oidc")
    public OidcUser oidc(Authentication authentication, HttpServletRequest request) {
        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        String registrationId = authToken.getAuthorizedClientRegistrationId();
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

        OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientRepository.loadAuthorizedClient(registrationId, authentication, request);

        OAuth2AccessToken auth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, oAuth2AuthorizedClient.getAccessToken().getTokenValue(), Instant.MIN, Instant.MAX);

        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
        idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC");
        idTokenClaims.put("preferred_username", "user");

        OidcUser principal = (OidcUser)authToken.getPrincipal();
        String idToken = principal.getIdToken().getTokenValue();

        OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.MIN, Instant.MAX, idTokenClaims);

        OidcUserService oidcUserService = new OidcUserService();
        oidcUserService.setOauth2UserService(new DefaultOAuth2UserService());

        OidcUser oidcUser = oidcUserService.loadUser(new OidcUserRequest(clientRegistration, auth2AccessToken, oidcIdToken));

        return oidcUser;
    }
}
*/
