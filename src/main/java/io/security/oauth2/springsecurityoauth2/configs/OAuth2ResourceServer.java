package io.security.oauth2.springsecurityoauth2.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import io.security.oauth2.springsecurityoauth2.signature.MacSecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.RSASecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.RsaPublicKeySecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.SecuritySigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
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
    private RSAKey rsaKey256;

    @Autowired
    private RSAKey rsaKey512;

    @Autowired
    private RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests((requests) -> requests.antMatchers("/").permitAll()
                .anyRequest().authenticated());
        http.userDetailsService(userDetailsService());
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(null), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) throws JOSEException {
        return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
    }

   /* @Bean
    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
    }*/

    /*@Bean
    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RSASecuritySigner rsaSecuritySigner, RSAKey rsaKey256) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaSecuritySigner,rsaKey256);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    private SecuritySigner securitySigner() {
        if (isAlg("RS256")){
            return rsaPublicKeySecuritySigner;

        }else if(isAlg("RS512")){
            return rsaSecuritySigner;

        }else if(isAlg("HS256")){
            return macSecuritySigner;
        }
        return null;
    }
    private JWK jwk() {

        if(isAlg("RS256")){
            return rsaKey256;

        }else if(isAlg("RS512")){
            return rsaKey512;

        }else if(isAlg("HS256")){
            return octetSequenceKey;
        }
        return null;
    }

    private boolean isAlg(String alg) {
        return properties.getJwt().getJwsAlgorithms().get(0).equals(alg);
    }
}
