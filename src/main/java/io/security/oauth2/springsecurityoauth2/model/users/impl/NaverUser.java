package io.security.oauth2.springsecurityoauth2.model.users.impl;

import io.security.oauth2.springsecurityoauth2.model.attributes.Attributes;
import io.security.oauth2.springsecurityoauth2.model.users.OAuth2ProviderUser;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class NaverUser extends OAuth2ProviderUser {

    public NaverUser(Attributes attributes, OAuth2User oAuth2User, ClientRegistration clientRegistration){
        super(attributes.getAttributes(), oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return (String)getAttributes().get("id");
    }

    @Override
    public String getUsername() {
        return (String)getAttributes().get("email");
    }

    @Override
    public String getPicture() {
        return (String)getAttributes().get("profile_image");
    }
}