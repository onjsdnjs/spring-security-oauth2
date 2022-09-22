package io.security.oauth2.springsecurityoauth2;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class JWKTest {

    public static void jwk() throws JOSEException, NoSuchAlgorithmException {

        // 비대칭키 JWK
        KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        rsaKeyPairGenerator.initialize(2048);

        KeyPair keyPair = rsaKeyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey1 = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("rsa-kid1")
                .build();

        RSAKey rsaKey2 = new RSAKeyGenerator(2048)
                .keyID("rsa-kid2")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Set.of(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        // 대칭키 JWK
        SecretKey secretKey = new SecretKeySpec(
                Base64.getDecoder().decode("bCzY/M48bbkwBEWjmNSIEPfwApcvXOnkCxORBEbPr+4="), "AES");

        OctetSequenceKey octetSequenceKey1 = new OctetSequenceKey.Builder(secretKey)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("secret-kid1").build();

        OctetSequenceKey octetSequenceKey2 = new OctetSequenceKeyGenerator(256)
                .keyID("secret-kid2")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Set.of(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.HS256)
                .generate();


        String kId;
        kId = rsaKey1.getKeyID();
        kId = rsaKey2.getKeyID();
        kId = octetSequenceKey1.getKeyID();
        kId = octetSequenceKey2.getKeyID();

        JWSAlgorithm alg;
        alg = JWSAlgorithm.RS256;
        alg = JWSAlgorithm.HS256;

        KeyType type;
        type = KeyType.RSA;
        type = KeyType.OCT;

        jwkSet(kId,alg,type,rsaKey1,rsaKey2,octetSequenceKey1,octetSequenceKey2);
    }

    private static void jwkSet(String kid, JWSAlgorithm alg,KeyType type,JWK ...jwk) throws KeySourceException {

        JWKSet jwkSet = new JWKSet(List.of(jwk));
        JWKSource<SecurityContext> jwkSource =(jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

        JWKMatcher jwkMatcher = new JWKMatcher.Builder()
                .keyType(type)
                .keyID(kid)
                .keyUses(KeyUse.SIGNATURE)
                .algorithms(alg)
                .build();

        JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
        List<JWK> jwks = jwkSource.get(jwkSelector, null);

        if(!jwks.isEmpty()){

            JWK jwk1 = jwks.get(0);

            KeyType keyType = jwk1.getKeyType();
            System.out.println("keyType = " + keyType);

            String keyID = jwk1.getKeyID();
            System.out.println("keyID = " + keyID);

            Algorithm algorithm = jwk1.getAlgorithm();
            System.out.println("algorithm = " + algorithm);

        }

        System.out.println("jwks = " + jwks);
    }
}
