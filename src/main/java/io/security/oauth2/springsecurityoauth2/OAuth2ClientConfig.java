package io.security.oauth2.springsecurityoauth2;

import io.security.oauth2.springsecurityoauth2.service.CustomOAuth2UserService;
import io.security.oauth2.springsecurityoauth2.service.CustomOidcUserService;
import io.security.oauth2.springsecurityoauth2.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests
                .antMatchers("/api/user")
                .access("hasRole('SCOPE_profile')")
//                .access("hasAuthority('SCOPE_profile')")
                .antMatchers("/api/oidc")
                .access("hasRole('SCOPE_openid')")
                //.access("hasAuthority('SCOPE_openid')")
                .antMatchers("/")
                .permitAll()
                .anyRequest().permitAll());
        http.oauth2Login(oauth2 -> oauth2.userInfoEndpoint(
                userInfoEndpointConfig -> userInfoEndpointConfig
                        .userService(customOAuth2UserService)
                        .oidcUserService(customOidcUserService)));
        http.logout().logoutSuccessUrl("/");
        return http.build();
   }

   /*@Bean // hasAuthority 일경우 정의하지 않는다
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper(){
       SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
       simpleAuthorityMapper.setPrefix("ROLE_");
       return simpleAuthorityMapper;
   }*/

    @Bean
    public GrantedAuthoritiesMapper customAuthorityMapper(){
        return new CustomAuthorityMapper();
    }
}
