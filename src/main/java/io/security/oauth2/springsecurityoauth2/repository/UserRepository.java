package io.security.oauth2.springsecurityoauth2.repository;

import io.security.oauth2.springsecurityoauth2.model.User;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    public User findByUsername(String username){
//        return User.builder().username(username).build();
        return null;
    }
    public void register(User user){
        System.out.println("user = " + user);
    };
}
