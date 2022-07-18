package io.resourceserver.resourceserver;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class PhotoController {

    @PostMapping("/photos")
    public List<Photo> photos(){

        Photo photo1 = getPhoto("1", "Photo 1 title", "Photo 1 description");
        Photo photo2 = getPhoto("2", "Photo 2 title", "Photo 2 description");

        return Arrays.asList(photo1, photo2);
    }
    private Photo getPhoto(String photoId, String photoTitle, String photoDescription) {
        Photo photo = new Photo();
        photo.setUserId("user");
        photo.setPhotoId(photoId);
        photo.setPhotoTitle(photoTitle);
        photo.setPhotoDescription(photoDescription);
        return photo;
    }
}