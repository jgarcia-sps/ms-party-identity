package com.bancoppel.security.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import com.bancoppel.security.auth.proto.TokenValidationServiceGrpc;
import com.bancoppel.security.auth.proto.ValidateTokenRequest;
import com.bancoppel.security.auth.proto.ValidateTokenResponse;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;

import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class TokenValidationGrpcService extends TokenValidationServiceGrpc.TokenValidationServiceImplBase {

    @Override
    public void validate(ValidateTokenRequest request,
                         StreamObserver<ValidateTokenResponse> responseObserver) {
       
        try {
            String tokenJEW = request.getAccessToken().replace("Bearer", "").replace(":", "").trim();
            
            
            System.out.println("--->"+tokenJEW);
            String tokenJET = decodeJWEToken(tokenJEW);
            System.out.println("--->"+tokenJET);
            
            ValidateTokenResponse response = ValidateTokenResponse.newBuilder()
                    .setAuthenticated(true)
                    .setAuthorized(true)
                    .addScopes("read")
                    .addPermissions("all")
                    .setSubject("service-a")
                    .setExpiresAt(System.currentTimeMillis() / 1000 + 3600)
                    .setError("1")
                    .setMessage("OK")
                    .build();
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception ex) {
            System.getLogger(TokenValidationGrpcService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }


    private String decodeJWEToken(String jwe) throws Exception{
        JWEObject jweObject = JWEObject.parse(jwe);

        System.out.println("Header: " + jweObject.getHeader());

        // 2️⃣ Cargar llave privada PKCS#8
        String pem = Files.readString(Path.of("D:/1-Actividades/1-COPPEL/DesarrolloJWE/parDellaves/private_key.pem"));

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
        return jweObject.getPayload().toString();
    }
}
