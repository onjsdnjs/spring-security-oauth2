package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public abstract class JwtAuthorizationFilter extends OncePerRequestFilter {
	private final JWSVerifier jwsVerifier;
	public JwtAuthorizationFilter(JWSVerifier jwsVerifier) {
		this.jwsVerifier = jwsVerifier;
	}

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

		if (tokenResolve(request, response, filterChain)){
			filterChain.doFilter(request,response);
			return;
		}
		String token = getToken(request);

		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(token);

			signedJWT.verify(jwsVerifier);

			String username = signedJWT.getJWTClaimsSet().getClaim("username").toString();
			List<String> authority = (List)signedJWT.getJWTClaimsSet().getClaim("authority");

			if (username != null) {
				UserDetails user = User.builder().username(username)
						.password("")
						.authorities(authority.get(0))
						.build();
				Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		filterChain.doFilter(request, response);
    }

	protected String getToken(HttpServletRequest request) {
		return request.getHeader("Authorization").replace("Bearer ", "");
	}

	protected boolean tokenResolve(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		String header = request.getHeader("Authorization");
		return header == null || !header.startsWith("Bearer ");
	}
}
