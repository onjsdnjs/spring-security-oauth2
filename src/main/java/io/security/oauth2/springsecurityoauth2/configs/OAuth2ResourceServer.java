package io.security.oauth2.springsecurityoauth2.configs;

import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServer {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.authorizeRequests((requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated());
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        http.userDetailsService(getUserDetailsService());
        http.addFilterBefore(new JwtAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private UserDetailsService getUserDetailsService() {

        User user = new User("user", "{noop}1234", Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager(user);

        return userDetailsManager;
    }

}
