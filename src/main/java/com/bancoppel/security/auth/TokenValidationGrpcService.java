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

import com.bancoppel.security.auth.proto.TokenValidationServiceGrpc;
import com.bancoppel.security.auth.proto.ValidateTokenRequest;
import com.bancoppel.security.auth.proto.ValidateTokenResponse;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
            String tokenJEW = request.getAccessToken().replace("Bearer", "").replace(":", "").trim();
            String pathPrivateKey = request.getPathPrivateKey();
            
            System.out.println("tokenJEW--->"+tokenJEW);
            System.out.println("Path--->"+pathPrivateKey);
            SignedJWT tokenJET = decodeJWEToken(tokenJEW,pathPrivateKey);

            JWTClaimsSet claims = tokenJET.getJWTClaimsSet();
            System.out.println("Audience--->"+claims.getAudience());

            List<String> roles = (ArrayList) claims.getClaim("https://empresanet.bancoppel.com/roles");
            System.out.println("roles:--->"+roles.getFirst());
            Map<String, Object> claimsListMap= claims.getClaims();

            claimsListMap.forEach((k,v) -> System.out.println("Key: " + k + ": Value: " + v));
            List<com.bancoppel.security.auth.proto.Claim> claimsList = request.getClaimsList();
            
            ValidateTokenResponse response = ValidateTokenResponse.newBuilder()
                    .setScopes("write read update")
                    .setAuthenticated(true)
                    .setAuthorized(true)
                    .setSubject("VhtS2wmrbuHi9smLWIdpzyguCi53Jwxj@clients")
                    .setExpires(System.currentTimeMillis() / 1000 + 3600)
                    .setClient("VhtS2wmrbuHi9smLWIdpzyguCi53Jwxj")
                    .setGrantType("client-credentials")
                    .setAudience("https://api.internal.company")
                    .setError(0)
                    .setMessage("OK")
                    .build();
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception ex) {
            System.getLogger(TokenValidationGrpcService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }


    private SignedJWT decodeJWEToken(String jwe, String pathPrivateKey) throws Exception{
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

      
       String innerJwt =jweObject.getPayload().toString();// 5️⃣ Extraer el JWT interno (JWS)
         System.out.println("--->"+innerJwt);
      

        String AUTH0_DOMAIN = "https://bancoppel-dev.coppel-dev.auth0app.com/"; // Reemplazar con tu dominio de Auth0
        String JWKS_URI = AUTH0_DOMAIN + ".well-known/jwks.json";

ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
              JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(JWKS_URI));

        // Especificar el algoritmo de firma esperado (RS256 es el predeterminado de Auth0)
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        System.out.println("SI PASO POR AQUI--->");
        jwtProcessor.setJWSKeySelector(keySelector);
        System.out.println("SI TERMINA ESTE PASO--->");
        return jweObject.getPayload().toSignedJWT();
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
