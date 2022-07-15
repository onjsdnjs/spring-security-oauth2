package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public JwtAuthenticationToken index(Authentication authentication, @AuthenticationPrincipal Jwt principal){

        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        String sub = jwtAuthenticationToken.getTokenAttributes().get("sub") + " is the subject";
        String sub1 = principal.getClaim("sub") + " is the subject";

        return jwtAuthenticationToken;
    }
}