package io.security.oauth2.springsecurityoauth2.common.util;

import io.security.oauth2.springsecurityoauth2.model.Attributes;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class OAuth2Utils {

    public static Attributes getMainAttributes(OAuth2User oAuth2User) {
        return Attributes.builder()
                .mainAttributes(oAuth2User.getAttributes())
                .build();
    }

    public static Attributes getSubAttributes(OAuth2User oAuth2User) {
        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get("response");
        return Attributes.builder()
                .subAttributes(subAttributes)
                .build();
    }

    public static Attributes getOtherAttributes(OAuth2User oAuth2User) {
        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get("kakao_account");
        Map<String, Object> otherAttributes = (Map<String, Object>)subAttributes.get("profile");

        return Attributes.builder()
                .subAttributes(subAttributes)
                .otherAttributes(otherAttributes)
                .build();
    }
}
