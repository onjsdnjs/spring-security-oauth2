package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
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
import java.util.UUID;

public abstract class JwtAuthorizationFilter extends OncePerRequestFilter {
	private JWSVerifier jwsVerifier;
	public JwtAuthorizationFilter(JWSVerifier jwsVerifier) {
		this.jwsVerifier = jwsVerifier;
	}

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

		String header = request.getHeader("Authorization");
		if(header == null || !header.startsWith("Bearer ")){
			filterChain.doFilter(request,response);
			return;
		}
		String token = header.replace("Bearer ", "");

		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(token);

			boolean verify = signedJWT.verify(jwsVerifier);

			if(verify){
				JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
				String username = jwtClaimsSet.getClaim("username").toString();
				List<String> authority = (List)jwtClaimsSet.getClaim("authority");

				if(username != null){
					UserDetails user = User.withUsername(username)
							.password(UUID.randomUUID().toString())
							.authorities(authority.get(0))
							.build();

					Authentication authentication =
							new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		filterChain.doFilter(request, response);
    }
}
