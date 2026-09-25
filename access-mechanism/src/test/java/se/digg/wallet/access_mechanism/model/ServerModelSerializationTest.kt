// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import se.digg.wallet.access_mechanism.utils.AppJson

class ServerModelSerializationTest {

    @Test
    fun `an hsm request without client id omits the field so the backend can supply it`() {
        val json = AppJson.encodeToString(HSMRequest(outerRequestJws = "jws"))

        assertFalse("clientId should be omitted when null", json.contains("clientId"))
        assertEquals("""{"outerRequestJws":"jws"}""", json)
    }

    @Test
    fun `an hsm request with client id includes it`() {
        val json = AppJson.encodeToString(HSMRequest(clientId = "abc", outerRequestJws = "jws"))

        assertEquals("""{"clientId":"abc","outerRequestJws":"jws"}""", json)
    }

    @Test
    fun `a state response without client id deserializes`() {
        val json = """
            {
              "status": "OK",
              "devAuthorizationCode": "code",
              "serverJwsPublicKey": null,
              "opaqueServerId": "server"
            }
        """.trimIndent()

        val state = AppJson.decodeFromString<StateResponse>(json)

        assertNull(state.clientId)
    }

    @Test
    fun `a key response tolerates unknown keys`() {
        val json = """
            {
              "public_key": {
                "kty": "EC",
                "crv": "P-256",
                "x": "cxaJAtOOm7Sa-e07S6kZx0D9WMUmNdSePv2zm0mgeh8",
                "y": "9BQyA1vpnJYKSvHVSmVE3Chiw61yIusEEUyO1F65_oo",
                "kid": "4dded7a5-c250-4d17-b747-d0ef2fd9533f"
              },
              "created_at": "2026-01-27T08:36:37.551226731+00:00"
            }
        """.trimIndent()

        val response = AppJson.decodeFromString<KeyResponse>(json)

        assertEquals("4dded7a5-c250-4d17-b747-d0ef2fd9533f", response.publicKey.keyID)
    }
}
