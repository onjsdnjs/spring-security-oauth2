package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@Configuration
public class OAuth2ClientConfig {

        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
        }

        private ClientRegistration googleClientRegistration() {
            return ClientRegistration.withRegistrationId("google")
                    .clientId("google-client-id")
                    .clientSecret("google-client-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid", "profile", "email", "address", "phone")
                    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                    .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                    .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                    .userNameAttributeName(IdTokenClaimNames.SUB)
                    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                    .clientName("Google")
                    .build();
        }
}
