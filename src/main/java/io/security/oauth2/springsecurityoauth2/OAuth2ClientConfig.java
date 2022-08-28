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
            return new InMemoryClientRegistrationRepository(this.keycloakClientRegistration());
        }

        private ClientRegistration keycloakClientRegistration() {
            return ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
                    .registrationId("keycloak")
                    .clientId("oauth2-client-app")
                    .clientSecret("CQueEWXZYmv7IIZVxbvh2uwxptXVaRcX")
                    .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
                    .build();
        }

}
