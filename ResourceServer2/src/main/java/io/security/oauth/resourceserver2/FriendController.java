package io.security.oauth.resourceserver2;

import io.security.sharedobject.Friend;
import io.security.sharedobject.Photo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class FriendController {

    @GetMapping("/friends")
    public List<Friend> friends(){

        Friend friend1 = getFriend("friend 1 ", 10 , "man ");
        Friend friend2 = getFriend("friend 2 ", 11 , "woman ");

        return Arrays.asList(friend1, friend2);
    }

    private Friend getFriend(String name, int age, String gender) {
        return Friend.builder()
                .name(name)
                .age(age)
                .gender(gender)
                .build();
    }
}