package io.security.oauth2.springsecurityoauth2.model;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class KeycloakUser extends OAuth2ProviderUser {

    public KeycloakUser(OAuth2User oAuth2User, ClientRegistration clientRegistration){
        super(oAuth2User.getAttributes(), oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return (String)getAttributes().get("sub");
    }

    @Override
    public String getUsername() {
        return (String)getAttributes().get("preferred_username");
    }

}
