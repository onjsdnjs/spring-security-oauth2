package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/user")
    public String user(Model model, Authentication authentication) {
        model.addAttribute("authentication",authentication);
        return "home";
    }

    @GetMapping("/oidc")
    public String oidc(Model model, Authentication authentication) {
        model.addAttribute("authentication",authentication);
        return "home";
    }
}
