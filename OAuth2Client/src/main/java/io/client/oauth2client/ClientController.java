package io.client.oauth2client;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ClientController {

    @GetMapping("/photos")
    public String client(String accessToken){

        return "client";
    }
}