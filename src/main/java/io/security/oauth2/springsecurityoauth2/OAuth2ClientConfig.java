package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class OAuth2ClientConfig {

        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
//            return new InMemoryClientRegistrationRepository(this.keycloakClientRegistration());
            return new InMemoryClientRegistrationRepository(clientRegistration());
        }

        private ClientRegistration keycloakClientRegistration() {
            return ClientRegistration.withRegistrationId("keycloak")
                    .clientId("oauth2-client-app")
                    .clientSecret("CQueEWXZYmv7IIZVxbvh2uwxptXVaRcX")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
                    .scope("openid", "profile", "email", "address", "phone")
                    .authorizationUri("http://localhost:8080/realms/oauth2/protocol/openid-connect/auth")
                    .tokenUri("http://localhost:8080/realms/oauth2/protocol/openid-connect/token")
                    .userInfoUri("http://localhost:8080/realms/oauth2/protocol/openid-connect/userinfo")
                    .userNameAttributeName("preferred_username")
                    .jwkSetUri("http://localhost:8080/realms/oauth2/protocol/openid-connect/certs")
                    .clientName("Keycloak")
                    .build();
        }


    @Bean
    public ClientRegistration clientRegistration() {

        return ClientRegistrations
                                    .fromIssuerLocation("http://localhost:8080/realms/oauth2")
                                    .clientId("oauth2-client-app")
                                    .clientSecret("CQueEWXZYmv7IIZVxbvh2uwxptXVaRcX")
                                    .clientName("keycloak")
                                    .registrationId("keycloak")
                                    .build();
    }
}
