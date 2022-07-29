package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/user")
    public String user(Model model, Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth2User) {
        System.out.println("oAuth2User = " + oAuth2User);
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken)authentication;
        model.addAttribute("provider",authenticationToken.getAuthorizedClientRegistrationId());

        return "home";
    }

    @GetMapping("/oidc") // 요청시 scope 에 openid 가 포함되어야 oidcUser 가 생성된다
    public String oidc(Model model, Authentication authentication, @AuthenticationPrincipal OidcUser oidcUser) {
        System.out.println("oidcUser = " + oidcUser);
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken)authentication;
        model.addAttribute("provider",authenticationToken.getAuthorizedClientRegistrationId());
        return "home";
    }
}
