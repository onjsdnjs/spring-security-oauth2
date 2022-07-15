package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.JWSVerifier;
import org.springframework.security.oauth2.jwt.JwtDecoder;

public class JwtAuthorizationRsaFilter extends JwtAuthorizationFilter {

    public JwtAuthorizationRsaFilter(JWSVerifier jwsVerifier) {
		super(jwsVerifier);
    }
}
