package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {

    @Autowired
    private DefaultOAuth2AuthorizedClientManager authorizedClientManager;
    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @GetMapping("/oauth2Login")
    public String oauth2Login(Model model, @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient oAuth2AuthorizedClient,
                              HttpServletResponse servletResponse, HttpServletRequest servletRequest) throws IOException {

        if(oAuth2AuthorizedClient != null) {

            OAuth2AuthorizationSuccessHandler authorizationSuccessHandler = (authorizedClient, authentication, attributes) ->
                    authorizedClientRepository
                            .saveAuthorizedClient(authorizedClient, authentication,
                                    (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                                    (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            authorizedClientManager.setAuthorizationSuccessHandler(authorizationSuccessHandler);

            ClientRegistration clientRegistration = oAuth2AuthorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = oAuth2AuthorizedClient.getAccessToken();

			OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2User oauth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(oAuth2AuthorizedClient.getClientRegistration(), accessToken));

            SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
            Collection<? extends GrantedAuthority> authorities = simpleAuthorityMapper.mapAuthorities(oauth2User.getAuthorities());
            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(oauth2User, authorities, clientRegistration.getRegistrationId());
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

            authorizationSuccessHandler.onAuthorizationSuccess(oAuth2AuthorizedClient, oAuth2AuthenticationToken, createAttributes(servletRequest, servletResponse));
            model.addAttribute("oAuth2AuthenticationToken",oAuth2AuthenticationToken);

        }

        return "home";
    }

    private static Map<String, Object> createAttributes(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(HttpServletRequest.class.getName(), servletRequest);
        attributes.put(HttpServletResponse.class.getName(), servletResponse);
        return attributes;
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest servletRequest, HttpServletResponse servletResponse, Authentication authentication){
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(servletRequest, servletResponse, authentication);
        return "index";
    }
}
