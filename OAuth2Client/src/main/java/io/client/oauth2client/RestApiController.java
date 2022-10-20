package io.client.oauth2client;

import io.security.sharedobject.AccessToken;
import io.security.sharedobject.Photo;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.Series.CLIENT_ERROR;
import static org.springframework.http.HttpStatus.Series.SERVER_ERROR;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final RestTemplate restTemplate;
    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/token")
    public OAuth2AccessToken token(@RegisteredOAuth2AuthorizedClient("springOAuth2") OAuth2AuthorizedClient oAuth2AuthorizedClient){
        return oAuth2AuthorizedClient.getAccessToken();
    }

    @GetMapping("/tokenExpire")
    public OAuth2Error tokenExpire(AccessToken accessToken){

        HttpHeaders header = new HttpHeaders();
        header.add("Authorization", "Bearer " + accessToken.getToken());
        HttpEntity<?> entity = new HttpEntity<>(header);
        String url = "http://localhost:8082/tokenExpire";
        ResponseEntity<OAuth2Error> response = restTemplate.exchange(url, HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

        return response.getBody();
    }

    @GetMapping("/newAccessToken")
    public OAuth2AccessToken newAccessToken(OAuth2AuthenticationToken authentication, HttpServletRequest request, HttpServletResponse response){

        OAuth2AuthorizedClient authorizedClient
                = authorizedClientService.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication.getName());

        if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {

            ClientRegistration clientRegistration = ClientRegistration.withClientRegistration
                    (authorizedClient.getClientRegistration()).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            OAuth2AuthorizedClient oAuth2AuthorizedClient =
                    new OAuth2AuthorizedClient(clientRegistration, authorizedClient.getPrincipalName(),
                            authorizedClient.getAccessToken(),authorizedClient.getRefreshToken());

            OAuth2AuthorizeRequest oAuth2AuthorizeRequest =
                    OAuth2AuthorizeRequest.withAuthorizedClient(oAuth2AuthorizedClient)
                            .principal(authentication)
                            .attribute(HttpServletRequest.class.getName(), request)
                            .attribute(HttpServletResponse.class.getName(), response)
                            .build();

            authorizedClient = oAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        }

        return authorizedClient.getAccessToken();
    }
}