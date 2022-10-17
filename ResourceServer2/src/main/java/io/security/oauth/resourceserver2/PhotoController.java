package io.security.oauth.resourceserver2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class PhotoController {

    @GetMapping("/photos")
    public List<Photo> photos(){

        Photo photo1 = getPhoto("ID1 ", "Title1 ", "Description1 ");
        Photo photo2 = getPhoto("ID2 ", "Title2 ", "Description2 ");

        return Arrays.asList(photo1, photo2);
    }

    @GetMapping("/remotePhotos")
    public List<Photo> remotePhotos(){

        Photo photo1 = getPhoto("RemoteID1 ", "RemoteTitle1 ", "RemoteDescription1 ");
        Photo photo2 = getPhoto("RemoteID2 ", "RemoteTitle2 ", "RemoteDescription2 ");

        return Arrays.asList(photo1, photo2);
    }
    private Photo getPhoto(String photoId, String photoTitle, String photoDescription) {
        Photo photo = new Photo();
        photo.setUserId("user ");
        photo.setPhotoId(photoId);
        photo.setPhotoTitle(photoTitle);
        photo.setPhotoDescription(photoDescription);
        return photo;
    }
}