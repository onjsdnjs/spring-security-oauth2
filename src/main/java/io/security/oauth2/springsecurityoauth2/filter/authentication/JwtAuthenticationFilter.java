package io.security.oauth2.springsecurityoauth2.filter.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import io.security.oauth2.springsecurityoauth2.dto.LoginDto;
import io.security.oauth2.springsecurityoauth2.signature.SecuritySigner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private SecuritySigner securitySigner;
    private JWK jwk;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, SecuritySigner securitySigner, JWK jwk) {

        this.authenticationManager = authenticationManager;
        this.securitySigner = securitySigner;
        this.jwk = jwk;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
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
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {

        UserDetails user = (UserDetails)authResult.getPrincipal();
        String jwtToken;
        try {
            MACSigner jwsSigner = new MACSigner(((OctetSequenceKey)jwk).toSecretKey());
            jwtToken = securitySigner.getJwtToken(jwsSigner, user, jwk);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Map<String, Object> detailMap = new HashMap<>();
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authResult;
        WebAuthenticationDetails details = (WebAuthenticationDetails)token.getDetails();

        detailMap.put("detail", details);
        detailMap.put("Authorization", "Bearer " + jwtToken);
        token.setDetails(detailMap);

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
