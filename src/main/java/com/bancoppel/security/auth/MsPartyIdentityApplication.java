package com.bancoppel.security.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;

@SpringBootApplication
public class MsPartyIdentityApplication {

public static void main(String[] args) throws Exception {

        String jwe = "eyJhbGciOiJSU0EtT0FFUC01MTIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoicUVqcXBDVzdndXUybVZsWU5hZGM0aGtfVk9MUVpHUTNXUlhxMzA0THAyMSJ9.JAvm0XEeCK_tUqdqY-F1oyrJfgALq0x-ZE8IZS6-Zpbj7nzx10CouTRON_4LLjEMnbd4OskgYHS0B-L5b745EBgknlMshtc0of7l5pO4AHwwIu47lzHYKCSWVkdruVOv9kenpOvRvwRasDQuJxcZ7zNql8f52d23J4tBWsjfmCPknTknuhsk_5rdg4J8HRs5lYNtUPNQsseDtm5M2vWFAfYP67uEf32tc-KXxntG0QWuWDWxOhyu5Stmb5sKqcKFgTgY9RSRoHQ67lG2k49gGrgImfx5w4e9WUEZwtTVU1Fgs3w6MsBthuS0_L0xCyk893BWUT3hlb5EzOdakLA6Wg.mystBpfCqwAKX_75.MDcL0fpXJa4slPkh21MriMl3JXfqNUwmNeMFZHEWii9p4NaDpRT-bwTKdzXTHXpgh4p7GILiLrrYT8RxrPwcfTeQeSEVsve1TgFryP8UQYquqgeu6WAbUy1CUhmzhkabshZIdJrAnFMUTxg1yYXsfwlKom_ycdSqIlaYgb2mKiY9F6lifHKuvh65V_y9imJPkfW8wgxuHJRA8-3G6BCarIs55Q7eWMgFXvY-oEXG9BP_tgUW8QPnxoKqyoHt00e_xmhhhxGPX-l1Ul6RH_XCuALWK_-q7mJ-YAtI0cCnmqXVeFtqgORAea-D9xWRiXH8FT6npK6kN6JKJM3iR49XnF3R-egfW7ktPOgSc4Sh7z3CL9qmuZnxiT3Bp0D8JkiKrFvk6CizFLHifRhvChmolccNARt1yaYeB17H0PxoHOj5ErEoaxUzjMi4D22bDamRWqbf8sXDigED46IDwsfvTSrgcYDfOMdRChHmSwwqzRkf23h6xeMxoEY0ZE6qJ4RU63V50bnBFKHV0mmH9quy0voWN6uGm0yTmLipv4aeSW6MNvrosSkm0sLr8lrZ08eJ8W4jP3CU8DDQOWU3b767XFf5a5czIAMzscNp0cDpDSGJVWFH6xwilCsVOduBPng7SdEpxEqP6kXGYxQvCOrERXRcTKRapoH7AGCwx0QVvh-2I59hq_POgxqPBXa3zhipMouC6IR7jn_9rW_NXnohyRRM-VcLcU5i9RE6V-o9GXWBdw8EvrzN9AyW5AYuJNDyMkPe1p4ZxrygNGxkjxUmpdEdGQtGk38xy3nJ-zE95xWoy-tNh7-elUf7wAJOQHdxnBg8tnQ8HQYfmub6eZo0aqAQ_YsQINlBWtEq-yWjju39h0dTli-5KCvgMlnFbVvi_HqCM8tM5AS1rllnd5zXNc-PcPvIIyrVw7sSJ8XIOrfCNnMw6tM4iY3IRfkAGaTgVB8g1MeEkIkQM5N34ezonJim99c.cof31WEzHnwRA1O_J7yYSw";
		// 1️⃣ Parsear JWE
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
        String payload = jweObject.getPayload().toString();

        System.out.println("Payload:");
        System.out.println(payload);
    }

}
