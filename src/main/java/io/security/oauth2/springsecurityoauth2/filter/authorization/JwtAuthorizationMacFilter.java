package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationMacFilter extends OncePerRequestFilter {
    private OctetSequenceKey jwk;

    public JwtAuthorizationMacFilter(OctetSequenceKey jwk) {
        this.jwk = jwk;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        System.out.println("header : " + header);
        String token = request.getHeader("Authorization").replace("Bearer ", "");

		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(token);
			MACVerifier macVerifier = new MACVerifier(jwk.toSecretKey());
			signedJWT.verify(macVerifier);

			String username = signedJWT.getJWTClaimsSet().getClaim("username").toString();
			String authority = signedJWT.getJWTClaimsSet().getClaim("authority").toString();

			if (username != null) {
				UserDetails user = User.builder().username(username)
						.authorities(authority)
						.build();
				Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}




        chain.doFilter(request, response);
    }

}
