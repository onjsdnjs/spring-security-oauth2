package io.client.oauth2client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.antMatchers("/","/photos").permitAll().anyRequest().authenticated());
        http.oauth2Login(Customizer.withDefaults());
        return http.build();
   }

   @Bean
    public RestTemplate restTemplate(){
       return new RestTemplate();
   }

    @Bean
    public JwtDecoderFactory<ClientRegistration> jwtDecoderFactory(){
        OidcIdTokenDecoderFactory oidcIdTokenDecoderFactory = new OidcIdTokenDecoderFactory();
        oidcIdTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> MacAlgorithm.HS256);
        return oidcIdTokenDecoderFactory;
    }
}
