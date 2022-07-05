package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomePageController {

	@GetMapping("/home")
	public String homePage() {
		return "home";
	}
}
