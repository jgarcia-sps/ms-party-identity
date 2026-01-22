package com.bancoppel.security.auth;

import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

import com.bancoppel.security.auth.proto.DataValidateToken;
import com.bancoppel.security.auth.proto.MetaValidateToken;
import com.bancoppel.security.auth.proto.TokenValidationServiceGrpc;
import com.bancoppel.security.auth.proto.ValidateTokenRequest;
import com.bancoppel.security.auth.proto.ValidateTokenResponse;
import com.google.protobuf.Value;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;


@GrpcService
public class TokenValidationGrpcService extends TokenValidationServiceGrpc.TokenValidationServiceImplBase {

    @Override
    public void validate(ValidateTokenRequest request,
                         StreamObserver<ValidateTokenResponse> responseObserver) {
       
        try {
            String tokenJWE = request.getAccessToken().replace("Bearer", "").replace(":", "").trim();
            System.out.println("tokenJEW--->"+tokenJWE);
            String strJWT=decodeJWEToken(tokenJWE);
            JWT jwt = JWTParser.parse(strJWT);

             System.out.println("jwt--->"+strJWT);
             
            JWTClaimsSet claims = validateSignature(jwt);    
            validateJWTClaims(claims,request);
           


            DataValidateToken data = DataValidateToken.newBuilder()
                    .setAuthenticated(true)
                    .setAuthorized(true)
                    .setJwt(strJWT)  
                    .putAllClaims(claims.getClaims().entrySet().stream()
                                .collect(Collectors.toMap(
                                        Map.Entry::getKey,
                                        e -> ProtoValueMapper.toValue(e.getValue())
                                    ))
                    )                 
                    .build();



MetaValidateToken meta = MetaValidateToken.newBuilder()
.setStatus("OK")
.setStatusCode(0)
.setTimestamp(Instant.now().toString())
.setMessage("SUCCESS")
.build();

 ValidateTokenResponse response = ValidateTokenResponse.newBuilder()
 .setMeta(meta)
 .setData(data)
 .build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception ex) {
            System.getLogger(TokenValidationGrpcService.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
        }
    }


    private String  decodeJWEToken(String jwe) throws Exception{
        JWEObject jweObject = JWEObject.parse(jwe); //1️⃣ Recibir y parsear el JWE

        
        JWEHeader header = jweObject.getHeader();

        System.out.println("Header: " + header);

        String kid = header.getKeyID();//2️⃣ Resolver el kid

        System.out.println("kid: " + kid);

        System.out.println("AWS_ACCESS_KEY_ID"+System.getenv("AWS_ACCESS_KEY_ID"));
        System.out.println("AWS_SECRET_ACCESS_KEY"+System.getenv("AWS_SECRET_ACCESS_KEY"));
        KmsClient kmsClient = KmsClient.builder()
            .region(Region.US_EAST_2)
            .build();

        String kmsKeyId = "arn:aws:kms:us-east-2:130537859737:key/d3e5506e-0447-4d15-93b8-aa7c35f7a834";
        AwsKmsRSADecrypter decrypter =new AwsKmsRSADecrypter(kmsClient, kmsKeyId);
        jweObject.decrypt(decrypter);

        return jweObject.getPayload().toString();
    }


    private JWTClaimsSet  validateSignature(JWT jwt) throws Exception{
       // String AUTH0_DOMAIN = "https://bancoppel-dev.coppel-dev.auth0app.com/";
        String AUTH0_DOMAIN = "https://dev-q8g17t3m0u4w8rf4.us.auth0.com/";        
        String JWKS_URI = AUTH0_DOMAIN + ".well-known/jwks.json";

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(JWKS_URI));

        // Especificar el algoritmo de firma esperado (RS256 es el predeterminado de Auth0)
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(jwt, null);
    }

    private void validateJWTClaims(JWTClaimsSet claims,ValidateTokenRequest request)throws Exception{
    Map<String, Object> claimsListMap= claims.getClaims();
    claimsListMap.forEach((k,v) -> System.out.println("Key: " + k + ": Value: " + v));

    Value issuerValue = request.getClaimsMap().get("issuer");
    String expectedIssuer = issuerValue.getStringValue();
    System.out.println("expectedIssuer--->"+expectedIssuer);
   
            if (!claims.getIssuer().contains(expectedIssuer)) {
                throw new BadJWTException("Issuer inválido");
            }
     Value audienceValue  = request.getClaimsMap().get("audience");
     String expectedAudience = audienceValue.getStringValue();
     System.out.println("expectedAudience--->"+expectedAudience);
     String[] arrayExpectedAudience = expectedAudience.split(",");
 
            if (Arrays.stream(arrayExpectedAudience)
                           .anyMatch(valor -> valor.equals(claims.getAudience()))) {
                throw new BadJWTException("Audience inválido");
            }
            // expiration
            if (claims.getExpirationTime() == null ||
                claims.getExpirationTime().before(new Date())) {
                throw new BadJWTException("Token expirado");
            }

    }
}
