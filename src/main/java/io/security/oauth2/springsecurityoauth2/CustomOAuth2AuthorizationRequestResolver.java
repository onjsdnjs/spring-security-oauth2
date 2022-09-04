package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private static final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
            .withPkce();
    private ClientRegistrationRepository clientRegistrationRepository;
    DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    private final AntPathRequestMatcher authorizationRequestMatcher;


    public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {

        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");

        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request);
        if (registrationId == null) {
            return null;
        }
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
        if(registrationId.equals("keycloakWithPKCE")){
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest, clientRegistration);

        }
        return defaultResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        if(clientRegistrationId.equals("keycloakWithPKCE")){
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest, clientRegistration);
        }
        return defaultResolver.resolve(request,clientRegistrationId);
    }
    private OAuth2AuthorizationRequest customResolve(OAuth2AuthorizationRequest authorizationRequest, ClientRegistration clientRegistration) {

        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.from(authorizationRequest);
        DEFAULT_PKCE_APPLIER.accept(builder);

        return builder.build();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher.matcher(request).getVariables()
                    .get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }
}
