package io.security.oauth2.springsecurityoauth2.controller;

import io.security.oauth2.springsecurityoauth2.common.enums.OAuth2Config;
import io.security.oauth2.springsecurityoauth2.common.util.OAuth2Utils;
import io.security.oauth2.springsecurityoauth2.model.Attributes;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model, OAuth2AuthenticationToken authentication, @AuthenticationPrincipal OAuth2User oAuth2User) {

        if (authentication != null) {

            String registrationId = authentication.getAuthorizedClientRegistrationId();

            Attributes attributes = OAuth2Utils.getMainAttributes(oAuth2User);
            String userName = (String) attributes.getMainAttributes().get("name");

            if (registrationId.equals(OAuth2Config.SocialType.NAVER.name())) {
                attributes = OAuth2Utils.getSubAttributes(oAuth2User,"response");
                userName = (String) attributes.getSubAttributes().get("name");

            } else if (registrationId.equals(OAuth2Config.SocialType.KAKAO.name())) {
                attributes = OAuth2Utils.getOtherAttributes(oAuth2User,"kakao_account","profile");
                userName = (String) attributes.getOtherAttributes().get("nickname");

            }

            model.addAttribute("user", userName);
        }
        return "index";
    }
}
