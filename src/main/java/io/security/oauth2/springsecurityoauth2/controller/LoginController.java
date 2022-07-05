package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class LoginController {

    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private HttpSecurity httpSecurity;

    @GetMapping("/client")
    public OAuth2User client(Authentication authentication, HttpServletRequest request){

        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        String clientRegistrationId = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();

        OAuth2AuthorizedClient oAuth2AuthorizedClient = authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, oAuth2AuthenticationToken, request);
        OAuth2AuthorizedClient oAuth2AuthorizedClient1 = authorizedClientService.loadAuthorizedClient(clientRegistrationId, oAuth2AuthenticationToken.getName());

        System.out.println("oAuth2AuthorizedClient = " + oAuth2AuthorizedClient);
        System.out.println("oAuth2AuthorizedClient1 = " + oAuth2AuthorizedClient1);

        OAuth2AccessToken accessToken = oAuth2AuthorizedClient.getAccessToken();

//        OAuth2UserService oAuth2UserService = httpSecurity.getSharedObject(OAuth2UserService.class);
		OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oauth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(oAuth2AuthorizedClient.getClientRegistration(), accessToken));

        return oauth2User;
    }

}
