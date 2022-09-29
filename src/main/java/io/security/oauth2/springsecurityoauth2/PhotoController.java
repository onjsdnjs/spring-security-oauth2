package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

    @GetMapping("/photos/1")
    public Photo photosUrl(){

        return Photo.builder()
                .photoId("1")
                .photoDescription("Photo 1 title")
                .userId("user1")
                .build();
    }

    @GetMapping("/photos/2")
    @PreAuthorize("hasAuthority('SCOPE_photo')")
    public Photo photosMethod(){

        return Photo.builder()
                .photoId("2")
                .photoDescription("Photo 2 title")
                .userId("user2")
                .build();
    }
}