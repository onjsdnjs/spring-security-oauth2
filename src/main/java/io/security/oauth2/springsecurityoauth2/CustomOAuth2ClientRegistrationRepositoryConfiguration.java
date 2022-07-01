package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ClientProperties.class)
@Conditional(ClientsConfiguredCondition.class)
@Order(Ordered.HIGHEST_PRECEDENCE - 100)
public class CustomOAuth2ClientRegistrationRepositoryConfiguration {

    @Bean
    @ConditionalOnMissingBean(ClientRegistrationRepository.class)
    InMemoryClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
        List<ClientRegistration> registrations = new ArrayList<>(
                CustomOAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(properties).values());
        return new InMemoryClientRegistrationRepository(registrations);
    }
}
