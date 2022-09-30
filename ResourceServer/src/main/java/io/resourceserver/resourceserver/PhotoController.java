package io.resourceserver.resourceserver;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class PhotoController {

    @GetMapping("/photos")
    public List<Photo> photos(){

        Photo photo1 = getBuild("1 ", "Photo 1 title ", "Photo is nice ", "user1");
        Photo photo2 = getBuild("2 ", "Photo 2 title ", "Photo is beautiful ", "user2");

        return Arrays.asList(photo1, photo2);
    }

    @GetMapping("/remotePhotos")
    public List<Photo> remotePhotos(){

        Photo photo1 = getBuild("Remote1 ", "Remote Photo 1 title ", "Remote Photo is nice ", "Remote user1");
        Photo photo2 = getBuild("Remote2 ", "Remote Photo 2 title ", "Remote Photo is beautiful ", "Remote user1");

        return Arrays.asList(photo1, photo2);
    }
    private Photo getBuild(String photoId, String photoTitle, String description, String user1) {
        return Photo.builder()
                .photoId(photoId)
                .photoTitle(photoTitle)
                .photoDescription(description)
                .userId(user1)
                .build();
    }
}