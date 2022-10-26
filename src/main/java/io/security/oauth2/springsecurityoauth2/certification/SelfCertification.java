package io.security.oauth2.springsecurityoauth2.certification;

import io.security.oauth2.springsecurityoauth2.model.users.social.ProviderUser;
import org.springframework.stereotype.Component;

@Component
public class SelfCertification {
    public boolean isCertificated(ProviderUser providerUser) {
        return true;
    }

    public void certificate(ProviderUser providerUser) {

    }
}
