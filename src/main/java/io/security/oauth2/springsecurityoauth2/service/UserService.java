package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.model.users.social.ProviderUser;
import io.security.oauth2.springsecurityoauth2.model.users.form.User;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    public void register(String registrationId, ProviderUser providerUser) {

        User user = User.builder().registrationId(registrationId)
                .id(providerUser.getId())
                .username(providerUser.getUsername())
                .password(providerUser.getPassword())
                .authorities(providerUser.getAuthorities())
                .provider(providerUser.getProvider())
                .email(providerUser.getEmail())
                .picture(providerUser.getPicture())
                .build();

        userRepository.register(user);
    }
}
