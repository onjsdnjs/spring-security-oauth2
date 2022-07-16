package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class PhotoController {

    @GetMapping("/photos")
    public List<Photo> index(Authentication authentication, @AuthenticationPrincipal Jwt principal){

        Photo photo1 = new Photo();
        photo1.setUserId("user");
        photo1.setPhotoId("1");
        photo1.setPhotoTitle("Photo 1 title");
        photo1.setPhotoDescription("Photo 1 description");

        Photo photo2 = new Photo();
        photo2.setUserId("user");
        photo2.setPhotoId("2");
        photo2.setPhotoTitle("Photo 2 title");
        photo2.setPhotoDescription("Photo 2 description");

        return Arrays.asList(photo1, photo2);
    }
}