package io.security.oauth2.springsecurityoauth2.certification;

import io.security.oauth2.springsecurityoauth2.model.users.User;
import io.security.oauth2.springsecurityoauth2.model.users.social.ProviderUser;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SelfCertification {

    private final UserRepository userRepository;
    public void checkCertification(ProviderUser providerUser) {
        //ci 와 소셜아이디 매핑 테이블에서 조회
        User user = userRepository.findByUsername(providerUser.getId());
//        if(user != null) {
            // ci 와 소셜아이디 매핑 테이블에 데이터가 존재하는 경우 해당 소셜 아이디로는 본인인증을 한 것으로 설정함
        boolean bool = providerUser.getProvider().equals("none") || providerUser.getProvider().equals("naver");
        providerUser.isCertificated(bool);
//        }
    }

    public void certificate(ProviderUser providerUser) {

    }
}
