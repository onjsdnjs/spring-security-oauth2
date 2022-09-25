package io.security.oauth2.springsecurityoauth2.filter.authorization;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

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
        String token = header.replace("Bearer ", "");

		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(token);
			MACVerifier macVerifier = new MACVerifier(jwk.toSecretKey());
			boolean verify = signedJWT.verify(macVerifier);

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

        chain.doFilter(request, response);
    }

}
