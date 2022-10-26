package io.security.oauth2.springsecurityoauth2.common.util;

import io.security.oauth2.springsecurityoauth2.common.enums.OAuth2Config;
import io.security.oauth2.springsecurityoauth2.model.Attributes;
import io.security.oauth2.springsecurityoauth2.model.users.PrincipalUser;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class OAuth2Utils {

    public static Attributes getMainAttributes(OAuth2User oAuth2User) {

        return Attributes.builder()
                .mainAttributes(oAuth2User.getAttributes())
                .build();
    }

    public static Attributes getSubAttributes(OAuth2User oAuth2User, String mainAttributesKey) {

        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get(mainAttributesKey);
        return Attributes.builder()
                .subAttributes(subAttributes)
                .build();
    }

    public static Attributes getOtherAttributes(OAuth2User oAuth2User, String mainAttributesKey, String subAttributesKey) {

        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get(mainAttributesKey);
        Map<String, Object> otherAttributes = (Map<String, Object>) subAttributes.get(subAttributesKey);

        return Attributes.builder()
                .subAttributes(subAttributes)
                .otherAttributes(otherAttributes)
                .build();
    }

    public static String authenticatedUserName(OAuth2AuthenticationToken authentication, PrincipalUser principalUser) {

        String userName;
        String registrationId = authentication.getAuthorizedClientRegistrationId();
        OAuth2User oAuth2User = principalUser.getProviderUser().getOAuth2User();

        // Google, Facebook, Apple
        Attributes attributes = OAuth2Utils.getMainAttributes(oAuth2User);
        userName = (String) attributes.getMainAttributes().get("name");

        // Naver
        if (registrationId.equals(OAuth2Config.SocialType.NAVER.getSocialName())) {
            attributes = OAuth2Utils.getSubAttributes(oAuth2User, "response");
            userName = (String) attributes.getSubAttributes().get("name");

            // Kakao
        } else if (registrationId.equals(OAuth2Config.SocialType.KAKAO.getSocialName())) {

            // OpenID Connect
            if (oAuth2User instanceof OidcUser) {
                attributes = OAuth2Utils.getMainAttributes(oAuth2User);
                userName = (String) attributes.getMainAttributes().get("nickname");

            } else {
                attributes = OAuth2Utils.getOtherAttributes(principalUser, "kakao_account", "profile");
                userName = (String) attributes.getOtherAttributes().get("nickname");
            }
        }
        return userName;
    }
}
