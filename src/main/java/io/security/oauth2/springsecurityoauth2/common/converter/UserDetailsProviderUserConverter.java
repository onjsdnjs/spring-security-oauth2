package io.security.oauth2.springsecurityoauth2.common.converter;

import io.security.oauth2.springsecurityoauth2.model.users.ProviderUser;
import io.security.oauth2.springsecurityoauth2.model.users.User;
import io.security.oauth2.springsecurityoauth2.model.users.form.FormUser;

public final class UserDetailsProviderUserConverter implements ProviderUserConverter<ProviderUserRequest,ProviderUser> {

    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {

        if(providerUserRequest.user() == null){
            return null;
        }

        User user = providerUserRequest.user();
        return FormUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities())
                .email(user.getEmail())
                .provider("none")
                .build();
    }
}
