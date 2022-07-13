package io.security.oauth2.springsecurityoauth2.filter.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import io.security.oauth2.springsecurityoauth2.dto.LoginDto;
import io.security.oauth2.springsecurityoauth2.signature.MacSecuritySigner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private HttpSecurity httpSecurity;
    private MacSecuritySigner macSecuritySigner;
    private OctetSequenceKey octetSequenceKey;

    public JwtAuthenticationFilter(HttpSecurity httpSecurity, MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) {
        this.httpSecurity = httpSecurity;
        this.macSecuritySigner = macSecuritySigner;
        this.octetSequenceKey = octetSequenceKey;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);

        ObjectMapper objectMapper = new ObjectMapper();
        LoginDto loginDto = null;
        try {

            loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        } catch (Exception e) {
            e.printStackTrace();
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        return authentication;
    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws ServletException, IOException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
        getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }
}
