package io.client.oauth2client;

import io.security.sharedobject.AccessToken;
import io.security.sharedobject.Photo;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

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

    private final DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

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
    public OAuth2AccessToken newAccessToken(AccessToken accessToken){

//        auth2AuthorizedClientManager.

        return null;
    }
}