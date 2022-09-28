package io.security.oauth2.springsecurityoauth2.filter.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

public class JwtAuthorizationRsaPublicKeyFilter extends JwtAuthorizationFilter {

    @Autowired
    private JwtDecoder jwtDecoder;

    public JwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) {
        super(null);
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (tokenResolve(request)){
            filterChain.doFilter(request,response);
            return;
        }

        if(jwtDecoder != null){

            Jwt jwt = jwtDecoder.decode(getToken(request));
            String username = jwt.getClaimAsString("username");
            List<String> authority = jwt.getClaimAsStringList("authority");

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
        filterChain.doFilter(request,response);
    }
}
