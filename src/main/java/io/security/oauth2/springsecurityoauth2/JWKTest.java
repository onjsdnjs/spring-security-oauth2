package io.security.oauth2.springsecurityoauth2;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

public class JWKTest {

    public static void jwk() throws JOSEException {

        // 대칭키 JWK
        OctetSequenceKey octetSequenceKey = new OctetSequenceKeyGenerator(256)
                .keyID("macKey")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Set.of(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.HS256)
                .generate();

        Base64URL keyValue = octetSequenceKey.getKeyValue();
        String s1 = keyValue.decodeToString();
        SecretKey secretKey = octetSequenceKey.toSecretKey();
        byte[] encoded = secretKey.getEncoded();
        String s = new String(encoded);
        Algorithm algorithm = octetSequenceKey.getAlgorithm();
        Set<KeyOperation> keyOperations = octetSequenceKey.getKeyOperations();
        KeyType keyType = octetSequenceKey.getKeyType();
        KeyUse keyUse = octetSequenceKey.getKeyUse();


        //비대칭키 JWK
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("rsaKey")
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Set.of(KeyOperation.SIGN))
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        PublicKey publicKey = rsaKey.toPublicKey();
        PrivateKey privateKey = rsaKey.toPrivateKey();
        KeyPair keyPair = rsaKey.toKeyPair();
        RSAKey rsaKey1 = rsaKey.toRSAKey();

        Algorithm algorithm2 = rsaKey.getAlgorithm();
        Set<KeyOperation> keyOperations2 = rsaKey.getKeyOperations();
        KeyType keyType2 = rsaKey.getKeyType();
        KeyUse keyUse2 = rsaKey.getKeyUse();
    }
}
