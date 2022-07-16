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

import java.util.Arrays;
import java.util.List;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/photos")
    public List<Photo> index(Authentication authentication, @AuthenticationPrincipal Jwt principal){

        PhotoRest photo1 = new PhotoRest();
        photo1.setPhotoId("1");
        photo1.setPhotoTitle("Photo 1 title");
        photo1.setPhotoDescription("Photo 1 description");
        photo1.setPhotoUrl("Photo 1 URL");

        PhotoRest photo2 = new PhotoRest();
        photo2.setPhotoId("2");
        photo2.setPhotoTitle("Photo 2 title");
        photo2.setPhotoDescription("Photo 2 description");
        photo2.setPhotoUrl("Photo 2 URL");

        return Arrays.asList(photo1, photo2);
    }
}