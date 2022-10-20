package io.resourceserver.resourceserver;

import io.security.sharedobject.Photo;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class PhotoController {

    @GetMapping("/photos")
    public List<Photo> photos(){

        Photo photo1 = PhotoService.getBuild("1 ", "Photo1 title ", "Photo is nice ", "user1 ");
        Photo photo2 = PhotoService.getBuild("2 ", "Photo2 title ", "Photo is beautiful ", "user2 ");

        return Arrays.asList(photo1, photo2);
    }

    @GetMapping("/remotePhotos")
    public List<Photo> remotePhotos(){

        Photo photo1 = PhotoService.getBuild("Remote1 ", "Remote Photo1 title ", "Remote Photo is nice ", "Remote user1 ");
        Photo photo2 = PhotoService.getBuild("Remote2 ", "Remote Photo2 title ", "Remote Photo is beautiful ", "Remote user1 ");

        return Arrays.asList(photo1, photo2);
    }

    @GetMapping("/tokenExpire")
    public OAuth2Error tokenExpire(){
        return new OAuth2Error("invalid token", "token is expired", null);
    }
}