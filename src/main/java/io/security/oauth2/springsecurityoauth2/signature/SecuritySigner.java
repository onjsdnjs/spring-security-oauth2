package io.security.oauth2.springsecurityoauth2.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;

public class SecuritySigner {

    public String getJwtToken(JWSSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("user")
                .issuer("http://localhost:8081")
                .claim("username", user.getUsername())
                .claim("authority", user.getAuthorities())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000 * 10))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder((JWSAlgorithm)jwk.getAlgorithm()).keyID(jwk.getKeyID()).build(), jwtClaimsSet);
        signedJWT.sign(jwsSigner);
        String jwtToken = signedJWT.serialize();

        return jwtToken;
    }
}
