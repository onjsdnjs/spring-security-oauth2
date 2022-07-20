package io.security.oauth2.springsecurityoauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequiredArgsConstructor
public class RegisteredClientController {

    private final RegisteredClientRepository registeredClientRepository;

    @GetMapping("/registeredClient")
    public RegisteredClient registeredClient(){
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("oauth2-client-app2");
        Set<String> scopes = registeredClient.getScopes();
        Set<AuthorizationGrantType> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes();
        return registeredClient;
    }
}
