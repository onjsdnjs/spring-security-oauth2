package io.security.oauth2.springsecurityoauth2.model.users;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Data
@Builder
public class User {

    private String registrationId;
    private String id;
    private String username;
    private String password;
    private String provider;
    private String email;
    private List<? extends GrantedAuthority> authorities;

}
