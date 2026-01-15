package com.bancoppel.security.auth;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.bancoppel.security.auth.proto.TokenValidationServiceGrpc;
import com.bancoppel.security.auth.proto.ValidateTokenRequest;
import com.bancoppel.security.auth.proto.ValidateTokenResponse;
import com.google.protobuf.Value;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class TokenValidationGrpcService extends TokenValidationServiceGrpc.TokenValidationServiceImplBase {

    @Override
    public void validate(ValidateTokenRequest request,
                         StreamObserver<ValidateTokenResponse> responseObserver) {
       
        try {
            String tokenJWE = request.getAccessToken().replace("Bearer", "").replace(":", "").trim();
            String pathPrivateKey = request.getPathPrivateKey();
            
            System.out.println("tokenJEW--->"+tokenJWE);
            System.out.println("Path--->"+pathPrivateKey);
            String strJWT=decodeJWEToken(tokenJWE,pathPrivateKey);
            JWT jwt = JWTParser.parse(strJWT);

             System.out.println("jwt--->"+jwt.toString());
            JWTClaimsSet claims = validateSignature(jwt);
            Map<String, Object> claimsListMap= claims.getClaims();
            claimsListMap.forEach((k,v) -> System.out.println("Key: " + k + ": Value: " + v));
            List<com.bancoppel.security.auth.proto.Claim> claimsList = request.getClaimsList();
            ValidateTokenResponse response = ValidateTokenResponse.newBuilder()
                    .setAuthenticated(true)
                    .setAuthorized(true)
                    .setJwt(strJWT)  
                    .putAllClaims(claimsListMap.entrySet().stream()
                                .collect(Collectors.toMap(
                                        Map.Entry::getKey,
                                        e -> ProtoValueMapper.toValue(e.getValue())
                                    ))
                    )                 
                    .setError(0)
                    .setMessage("OK")
                    .build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception ex) {
            System.getLogger(TokenValidationGrpcService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }


    private String  decodeJWEToken(String jwe, String pathPrivateKey) throws Exception{
        JWEObject jweObject = JWEObject.parse(jwe); //1️⃣ Recibir y parsear el JWE

        
        JWEHeader header = jweObject.getHeader();

        System.out.println("Header: " + header);

        String kid = header.getKeyID();//2️⃣ Resolver el kid

        System.out.println("kid: " + kid);
        /*
           // AQUI VA KMS [3] Obtener Private Key desde KMS
           3️⃣ Obtener la Private Key desde KMS (NO del filesystem)
           // Este kid debe existir en tu KMS / Key Vault.
          RSAPrivateKey privateKey = kmsClient.getPrivateKeyByKid(kid);
        */
    
        String pem = Files.readString(Path.of(pathPrivateKey));

        String privateKeyPem = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

       
        RSADecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);
        jweObject.decrypt(decrypter);//4️⃣ Desencriptar el JWE
        return jweObject.getPayload().toString();
    }


    private JWTClaimsSet  validateSignature(JWT jwt) throws Exception{
        String AUTH0_DOMAIN = "https://bancoppel-dev.coppel-dev.auth0app.com/";
       // String AUTH0_DOMAIN = "https://dev-q8g17t3m0u4w8rf4.us.auth0.com/";        
        String JWKS_URI = AUTH0_DOMAIN + ".well-known/jwks.json";

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(JWKS_URI));

        // Especificar el algoritmo de firma esperado (RS256 es el predeterminado de Auth0)
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);

          // 5️⃣ Validaciones de claims
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
/*
            if (!issuer.equals(claims.getIssuer())) {
                throw new BadJWTException("Issuer inválido");
            }

            if (!claims.getAudience().contains(expectedAudience)) {
                throw new BadJWTException("Audience inválido");
            }
 */
            if (claims.getExpirationTime() == null ||
                claims.getExpirationTime().before(new Date())) {
                throw new BadJWTException("Token expirado");
            }
        });

        return jwtProcessor.process(jwt, null);
    }

    private void validateJWTClaims( List<com.bancoppel.security.auth.proto.Claim> claimsList, SignedJWT signedJWT)throws Exception{
    JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        if (!claims.getIssuer().equals("https://TU_DOMINIO.auth0.com/")) {
            throw new SecurityException("Invalid issuer");
        }

        // audience
        if (!claims.getAudience().contains("tu-api")) {
            throw new SecurityException("Invalid audience");
        }

        // expiration
        if (claims.getExpirationTime().before(new Date())) {
            throw new SecurityException("Token expired");
        }

    }
}
