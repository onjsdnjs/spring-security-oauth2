package io.security.oauth2.springsecurityoauth2.controller;

import io.security.oauth2.springsecurityoauth2.model.users.PrincipalUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal PrincipalUser principalUser) {

        String view = "index";

        // 강의 때와 코드가 조금 틀립니다 조만간 업데이트 하겠습니다.
        String userName = principalUser.providerUser().getUsername();

        model.addAttribute("user", userName);
        model.addAttribute("provider", principalUser.providerUser().getProvider());

        if (!principalUser.providerUser().isCertificated()) view = "selfcert";

        return view;
}
}