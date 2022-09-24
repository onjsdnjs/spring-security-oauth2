package io.security.oauth2.springsecurityoauth2.configs;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationMacFilter;
import io.security.oauth2.springsecurityoauth2.signature.MacSecuritySigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.Arrays;

@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServer {

    @Autowired
    private MacSecuritySigner macSecuritySigner;

    @Autowired
    private OctetSequenceKey octetSequenceKey;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests((requests) -> requests.antMatchers("/").permitAll().anyRequest().authenticated());
        http.userDetailsService(getUserDetailsService());
        http.addFilterBefore(new JwtAuthenticationFilter(http,macSecuritySigner, octetSequenceKey), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtAuthorizationMacFilter(octetSequenceKey), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private UserDetailsService getUserDetailsService() {

        User user = new User("user", "{noop}1234", Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager(user);
        return userDetailsManager;
    }
}