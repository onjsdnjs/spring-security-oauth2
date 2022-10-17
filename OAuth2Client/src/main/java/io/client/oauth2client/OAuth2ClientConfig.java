package io.client.oauth2client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration
public class OAuth2ClientConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.antMatchers("/","/photos").permitAll().anyRequest().authenticated());
        http.oauth2Login(authLogin -> authLogin.defaultSuccessUrl("/"));
        return http.build();
   }

   @Bean
    public RestTemplate restTemplate(){
       return new RestTemplate();
   }
}
