package io.security.oauth2.springsecurityoauth2.certification;

import io.security.oauth2.springsecurityoauth2.model.users.User;
import io.security.oauth2.springsecurityoauth2.model.users.social.ProviderUser;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class SelfCertification {

    @Autowired
    private UserRepository userRepository;
    public boolean isCertificated(ProviderUser providerUser) {

        if(providerUser.getProvider().equals("naver")) {
            return true;
        }
        return false;

        /*User user = userRepository.findByUsername(providerUser.getUsername());
        return user != null;*/
    }

    public void certificate(ProviderUser providerUser) {

    }
}
