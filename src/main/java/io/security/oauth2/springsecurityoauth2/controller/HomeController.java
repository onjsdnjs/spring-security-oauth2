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
    public String user(Model model, Authentication authentication) {

        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        System.out.println("oAuth2User = " + oAuth2User);

        model.addAttribute("oAuth2User",oAuth2User);
        model.addAttribute("authentication",authentication);

        return "home";
    }

    @GetMapping("/oidc")
    public String oidc(Model model, Authentication authentication, @AuthenticationPrincipal OidcUser oidcUser) {
        model.addAttribute("oAuth2User",oidcUser);
        model.addAttribute("authentication",authentication);
        return "home";
    }
}
