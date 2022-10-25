package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.model.attributes.Attributes;
import io.security.oauth2.springsecurityoauth2.model.users.*;
import io.security.oauth2.springsecurityoauth2.model.users.impl.GoogleUser;
import io.security.oauth2.springsecurityoauth2.model.users.impl.KakaoUser;
import io.security.oauth2.springsecurityoauth2.model.users.impl.NaverUser;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Getter
public abstract class AbstractOAuth2UserService {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest){
        User user = userRepository.findByUsername(providerUser.getUsername());

        if(user == null){
            ClientRegistration clientRegistration = userRequest.getClientRegistration();
            userService.register(clientRegistration.getRegistrationId(),providerUser);
        }else{
            System.out.println("userRequest = " + userRequest);
        }
    }

    public ProviderUser providerUser(ClientRegistration clientRegistration, OAuth2User oAuth2User){

        String registrationId = clientRegistration.getRegistrationId();

        if(registrationId.equals("google")){

            Attributes attributes = Attributes.builder()
                    .attributes(oAuth2User.getAttributes())
                    .build();

            return new GoogleUser(attributes, oAuth2User,clientRegistration);
        }
        else if(registrationId.equals("naver")){

            Map<String, Object> mainAttributes = (Map<String, Object>)oAuth2User.getAttributes().get("response");
            Attributes attributes = Attributes.builder()
                    .attributes(mainAttributes)
                    .build();

            return new NaverUser(attributes, oAuth2User,clientRegistration);
        }
        else if(registrationId.equals("kakao")){

            Map<String, Object> mainAttributes = (Map<String, Object>)oAuth2User.getAttributes().get("kakao_account");
            Map<String, Object> subAttributes = (Map<String, Object>)mainAttributes.get("profile");

            Attributes attributes = Attributes.builder()
                    .attributes(mainAttributes)
                    .subAttributes(subAttributes)
                    .build();
            return new KakaoUser(attributes, oAuth2User,clientRegistration);
        }
        return null;
    }
}
