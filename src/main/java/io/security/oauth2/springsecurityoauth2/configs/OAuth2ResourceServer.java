package io.security.oauth2.springsecurityoauth2.configs;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaFilter;
import io.security.oauth2.springsecurityoauth2.signature.MacSecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.RSASecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.SecuritySigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServer {

    @Autowired
    private OAuth2ResourceServerProperties properties;

    @Autowired
    private MacSecuritySigner macSecuritySigner;

    @Autowired
    private OctetSequenceKey octetSequenceKey;

    @Autowired
    private RSASecuritySigner rsaSecuritySigner;

    @Autowired
    private RSAKey rsaKey;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests((requests) -> requests.antMatchers("/login","/").permitAll().anyRequest().authenticated());
        http.userDetailsService(getUserDetailsService());
        http.addFilterBefore(new JwtAuthenticationFilter(http,securitySigner(), jwk()), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey())), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private UserDetailsService getUserDetailsService() {

        User user = new User("user", "{noop}1234", Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager(user);

        return userDetailsManager;
    }
    private SecuritySigner securitySigner() {

        if(properties.getJwt().getJwsAlgorithms().get(0).equals("RS256")){
            return rsaSecuritySigner;

        }else if(properties.getJwt().getJwsAlgorithms().get(0).equals("HS256")){
            return macSecuritySigner;
        }
        return null;
    }

    private JWK jwk() {

        if(properties.getJwt().getJwsAlgorithms().get(0).equals("RS256")){
            return rsaKey;

        }else if(properties.getJwt().getJwsAlgorithms().get(0).equals("HS256")){
            return octetSequenceKey;
        }
        return null;
    }
}
