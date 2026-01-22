package com.bancoppel.security.auth;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

public class AwsKmsRSADecrypter implements JWEDecrypter {

    private final KmsClient kmsClient;
    private final String keyId;
    private final JWEJCAContext jcaContext = new JWEJCAContext();

    public AwsKmsRSADecrypter(KmsClient kmsClient, String keyId) {
        this.kmsClient = kmsClient;
        this.keyId = keyId;
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            byte[] aad
    ) throws JOSEException {

        // 1️⃣ Descifrar CEK con AWS KMS
        byte[] cekBytes = kmsClient.decrypt(
                DecryptRequest.builder()
                        .keyId(keyId)
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                        .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                        .build()
        ).plaintext().asByteArray();

        SecretKey cek = new SecretKeySpec(cekBytes, "AES");

        // 2️⃣ Descifrar el payload (Nimbus)
    return ContentCryptoProvider.decrypt(
            header,
            header.toBase64URL(),
            iv,
            cipherText,
            authTag,
            cek,
            jcaContext
    );
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return Set.of(JWEAlgorithm.RSA_OAEP_256);
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return Set.of(EncryptionMethod.A256GCM);
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jcaContext;
    }
}