package io.security.cors2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CorsController {
    @GetMapping("/users")
    public String users(){
        return "hong gil dong";
    }
}
