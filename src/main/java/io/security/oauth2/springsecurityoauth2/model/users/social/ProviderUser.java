package io.security.oauth2.springsecurityoauth2.model.users.social;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.List;
import java.util.Map;

public interface ProviderUser {

    String getId();
    String getUsername();
    String getPassword();
    String getEmail();
    String getProvider();
    String getPicture();
    List<? extends GrantedAuthority> getAuthorities();
    Map<String, Object> getAttributes();
    OAuth2User getOAuth2User();
    boolean isCertificated();
    void isCertificated(boolean isCertificated);

}
