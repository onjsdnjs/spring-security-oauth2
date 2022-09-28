package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication, @AuthenticationPrincipal Jwt principal) throws URISyntaxException {


        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        String sub = jwtAuthenticationToken.getTokenAttributes().get("sub") + " is the subject";
        String sub1 = principal.getClaim("sub") + " is the subject";

        String token = principal.getTokenValue();

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization","Bearer " + token);
        RequestEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET, new URI("http://localhost:9090/user"));
        ResponseEntity<String> exchange = restTemplate.exchange(request, String.class);

        String body = exchange.getBody();

        return authentication;
    }
}
