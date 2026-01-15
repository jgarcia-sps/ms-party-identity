package com.bancoppel.security.auth;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.google.protobuf.ListValue;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;

public class ProtoValueMapper {

    public static Value toValue(Object obj) {

        if (obj == null) {
            return Value.newBuilder()
                    .setNullValueValue(0)
                    .build();
        }

        // 🔹 String seguro (Nimbus ya entrega UTF-8 válido)
        if (obj instanceof String) {
            return Value.newBuilder()
                    .setStringValue((String) obj)
                    .build();
        }

        // 🔹 Boolean
        if (obj instanceof Boolean) {
            return Value.newBuilder()
                    .setBoolValue((Boolean) obj)
                    .build();
        }

        // 🔹 Number (exp, iat, nbf, auth_time)
        if (obj instanceof Number) {
            return Value.newBuilder()
                    .setNumberValue(((Number) obj).doubleValue())
                    .build();
        }

        // 🔹 Map (claims anidados)
        if (obj instanceof Map) {
            Struct.Builder structBuilder = Struct.newBuilder();
            Map<?, ?> map = (Map<?, ?>) obj;

            map.forEach((k, v) ->
                    structBuilder.putFields(
                            String.valueOf(k),
                            toValue(v)
                    )
            );

            return Value.newBuilder()
                    .setStructValue(structBuilder.build())
                    .build();
        }

        // 🔹 List estándar (por compatibilidad)
        if (obj instanceof List) {
            ListValue.Builder listBuilder = ListValue.newBuilder();
            List<?> list = (List<?>) obj;

            list.forEach(item ->
                    listBuilder.addValues(toValue(item))
            );

            return Value.newBuilder()
                    .setListValue(listBuilder.build())
                    .build();
        }

        // 🔹 byte[] (raro, pero visto en extensiones)
        if (obj instanceof byte[]) {
            return Value.newBuilder()
                    .setStringValue(new String((byte[]) obj, StandardCharsets.UTF_8))
                    .build();
        }

        if (obj instanceof Date) {
            return Value.newBuilder()
                    .setNumberValue(((Date) obj).getTime() / 1000.0)
                    .build();
        }

        // 🔹 Fallback seguro
        return Value.newBuilder()
                .setStringValue(String.valueOf(obj))
                .build();
    }
}