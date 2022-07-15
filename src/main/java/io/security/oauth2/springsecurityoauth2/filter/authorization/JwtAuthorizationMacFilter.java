package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import javax.servlet.http.HttpServletRequest;

public class JwtAuthorizationMacFilter extends JwtAuthorizationFilter {
	private OctetSequenceKey jwk;

    public JwtAuthorizationMacFilter(OctetSequenceKey jwk, JWSVerifier jwsVerifier) {
		super(jwk, jwsVerifier);
    }

	@Override
	protected void executeDecoding(HttpServletRequest request, JWSVerifier jwsVerifier, String token) {

	}

}
