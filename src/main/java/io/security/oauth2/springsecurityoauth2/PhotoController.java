package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

    @GetMapping("/photos/1")
    public Photo photo1(){
        return Photo.builder()
                .photoId("1")
                .photoTitle("Photo 1 title")
                .photoDescription("Photo is nice")
                .userId("user1")
                .build();
    }

    @GetMapping("/photos/2")
//    @PreAuthorize("hasAnyAuthority('SCOPE_photo')")
    public Photo photo2(){
        return Photo.builder()
                .photoId("2")
                .photoTitle("Photo 2 title")
                .photoDescription("Photo is beauty")
                .userId("user2")
                .build();
    }

    @GetMapping("/photos/3")
    public Photo photo3(){
        return Photo.builder()
                .photoId("3")
                .photoTitle("Photo 3 title")
                .photoDescription("Photo is beauty")
                .userId("user3")
                .build();
    }

}
