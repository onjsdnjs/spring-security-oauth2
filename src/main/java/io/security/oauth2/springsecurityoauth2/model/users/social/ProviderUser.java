package io.security.oauth2.springsecurityoauth2.model.users.social;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;

public interface ProviderUser {

    public String getId();
    public String getUsername();
    public String getPassword();
    public String getEmail();
    public String getProvider();
    public String getPicture();
    public List<? extends GrantedAuthority> getAuthorities();
    public Map<String, Object> getAttributes();

}
