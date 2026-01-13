package com.bancoppel.security.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import com.bancoppel.security.auth.proto.TokenValidationServiceGrpc;
import com.bancoppel.security.auth.proto.ValidateTokenRequest;
import com.bancoppel.security.auth.proto.ValidateTokenResponse;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

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
            List<com.bancoppel.security.auth.proto.Claim> claimsList = request.getClaimsList();
            
            ValidateTokenResponse response = ValidateTokenResponse.newBuilder()
                    .setScopes("write read update")
                    .addPermissions("read")
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
        JWEObject jweObject = JWEObject.parse(jwe);

        System.out.println("Header: " + jweObject.getHeader());

        // 2️⃣ Cargar llave privada PKCS#8
        String pem = Files.readString(Path.of(pathPrivateKey));

        String privateKeyPem = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // 3️⃣ Desencriptar
        RSADecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);
        jweObject.decrypt(decrypter);

        // 4️⃣ Resultado
        
         System.out.println("--->"+jweObject.getPayload().toString());
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
