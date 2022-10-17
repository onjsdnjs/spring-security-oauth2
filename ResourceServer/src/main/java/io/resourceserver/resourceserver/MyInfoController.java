package io.resourceserver.resourceserver;

import io.security.sharedobject.AccessToken;
import io.security.sharedobject.Friend;
import io.security.sharedobject.MyInfo;
import io.security.sharedobject.Photo;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class MyInfoController {

    private final RestTemplate restTemplate;

    @GetMapping("/myInfo")
    public MyInfo myInfo(JwtAuthenticationToken authenticationToken){

        HttpHeaders header = new HttpHeaders();
        header.add("Authorization", "Bearer " + authenticationToken.getToken().getTokenValue());
        HttpEntity<?> entity = new HttpEntity<>(header);
        String url = "http://localhost:8083/friends";
        ResponseEntity<List<Friend>> response = restTemplate.exchange(url, HttpMethod.GET, entity, new ParameterizedTypeReference<>(){});

        Photo photo1 = PhotoService.getBuild("1 ", "Album1 title ", "Album is nice ", "user1");
        Photo photo2 = PhotoService.getBuild("2 ", "Album2 title ", "Album is beautiful ", "user2");

        return MyInfo.builder().photos(Arrays.asList(photo1, photo2)).friends(response.getBody()).build();
    }
}