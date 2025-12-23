package com.bancoppel.security.auth;

import com.bancoppel.security.auth.proto.TokenValidationServiceGrpc;
import com.bancoppel.security.auth.proto.ValidateTokenRequest;
import com.bancoppel.security.auth.proto.ValidateTokenResponse;

import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class TokenValidationGrpcService extends TokenValidationServiceGrpc.TokenValidationServiceImplBase {

    @Override
    public void validate(ValidateTokenRequest request,
                         StreamObserver<ValidateTokenResponse> responseObserver) {
       
    String token = request.getAccessToken().replace("Bearer", "").replace(":", "").trim();
   

    System.out.println("--->"+token);

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
    }
}
