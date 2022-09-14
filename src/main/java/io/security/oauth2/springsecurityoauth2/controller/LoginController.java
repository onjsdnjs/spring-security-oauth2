package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class LoginController {
    @GetMapping("/oauth2Login")
    public String oauth2Login(Model model, HttpServletResponse servletResponse, HttpServletRequest servletRequest) throws IOException {
        return "redirect:/";
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletResponse response, HttpServletRequest request) throws IOException {

        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request,response,authentication);

        return "redirect:/";
    }
}
