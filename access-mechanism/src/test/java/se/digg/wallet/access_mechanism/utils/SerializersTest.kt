// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.utils

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import se.digg.wallet.access_mechanism.utils.AppJson
import org.junit.Assert.assertEquals
import org.junit.Test
import se.digg.wallet.access_mechanism.model.KeyInfo
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant

class SerializersTest {

    @Test
    fun testKeyInfoDeserialization() {
        val jsonInput = """
            {
              "created_at": "2026-01-27T08:36:37.551226731+00:00",
              "public_key": {
                "kty": "EC",
                "crv": "P-256",
                "x": "cxaJAtOOm7Sa-e07S6kZx0D9WMUmNdSePv2zm0mgeh8",
                "y": "9BQyA1vpnJYKSvHVSmVE3Chiw61yIusEEUyO1F65_oo",
                "kid": "4dded7a5-c250-4d17-b747-d0ef2fd9533f"
              }
            }
        """.trimIndent()

        val keyInfo = AppJson.decodeFromString<KeyInfo>(jsonInput)

        assertEquals(Instant.parse("2026-01-27T08:36:37.551226731+00:00"), keyInfo.createdAt)

        val publicKey = keyInfo.publicKey
        assertEquals("4dded7a5-c250-4d17-b747-d0ef2fd9533f", publicKey.keyID)
        assertEquals("EC", publicKey.keyType.value)

        if (keyInfo.publicKey is ECKey) {
            assertEquals("cxaJAtOOm7Sa-e07S6kZx0D9WMUmNdSePv2zm0mgeh8", publicKey.x.toString())
            assertEquals("9BQyA1vpnJYKSvHVSmVE3Chiw61yIusEEUyO1F65_oo", publicKey.y.toString())
            assertEquals("P-256", publicKey.curve.name)
        }
    }

    @Test
    fun testJwkSerializer() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()

        val jwk = ECKey.Builder(Curve.P_256, keyPair.public as ECPublicKey)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("1")
            .build()

        val jsonString = AppJson.encodeToString(JwkSerializer, jwk)

        val decodedJwk = AppJson.decodeFromString(JwkSerializer, jsonString)

        assertEquals(jwk.toJSONObject(), decodedJwk.toJSONObject())
    }
}
