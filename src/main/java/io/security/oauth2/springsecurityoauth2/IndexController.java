package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public BearerTokenAuthentication index(Authentication authentication, @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal){

        BearerTokenAuthentication bearerTokenAuthentication = (BearerTokenAuthentication) authentication;
        String sub = bearerTokenAuthentication.getTokenAttributes().get("sub") + " is the subject";
        String sub1 = principal.getAttribute("sub") + " is the subject";

        return bearerTokenAuthentication;
    }
}