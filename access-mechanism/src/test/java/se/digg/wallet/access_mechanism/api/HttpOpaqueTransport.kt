// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.model.HSMRequest
import se.digg.wallet.access_mechanism.model.StateResponse
import se.digg.wallet.access_mechanism.utils.AppJson
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.interfaces.ECPublicKey

/**
 * Test-only [OpaqueTransport] backed by [HttpURLConnection].
 *
 * POSTs device-state registration to `/hsm/v1/device-states` and every signed operation to
 * `/hsm/v1/requests`. The latter returns an `AsyncResponseDto`; on a synchronous backend it
 * carries the worker `result` (the server's compact JWS) plus the updated `stateJws`.
 *
 * The transport tracks the latest `stateJws` and threads it into later requests so the
 * device state is carried by the client rather than relying on the BFF's server-side store.
 *
 * Lives in the test source set only — the library does not ship a concrete transport.
 */
class HttpOpaqueTransport(private val baseUrl: String) : OpaqueTransport {

    /** The most recent signed device state, seeded at registration and refreshed by each response. */
    private var latestStateJws: String? = null

    override suspend fun registerState(
        publicKey: ECPublicKey,
        overwrite: Boolean,
        ttl: String?
    ): StateResponse {
        // Send the public JWK with its RFC 7638 thumbprint as `kid`, matching how the
        // client derives its OPAQUE identity (OpaqueCryptoManager.clientKeyThumbprint).
        val kid = ECKey.Builder(Curve.P_256, publicKey).build().computeThumbprint("SHA-256").toString()
        val publicJwkJson =
            ECKey.Builder(Curve.P_256, publicKey).keyID(kid).build().toPublicJWK().toJSONString()
        val ttlField = ttl?.let { ""","ttl":"$it"""" } ?: ""
        val body = """{"publicKey":$publicJwkJson,"overwrite":$overwrite$ttlField}"""

        val responseBody = post("/hsm/v1/device-states", body)
        return AppJson.decodeFromString<StateResponse>(responseBody).also {
            latestStateJws = it.stateJws
        }
    }

    override suspend fun perform(request: HSMRequest, operation: HSMOperationType): String {
        val effective = request.copy(stateJws = request.stateJws ?: latestStateJws)
        val responseBody = post("/hsm/v1/requests", AppJson.encodeToString(effective))
        val async = AppJson.decodeFromString<AsyncResponse>(responseBody)
        async.stateJws?.let { latestStateJws = it }
        return async.result ?: throw IOException(
            "Request not completed synchronously (status=${async.status}); no result in /hsm/v1/requests response"
        )
    }

    /** Mirrors the backend `AsyncResponseDto` (camelCase). Only the fields we consume are modeled. */
    @Serializable
    private data class AsyncResponse(
        val correlationId: String? = null,
        val status: String? = null,
        val result: String? = null,
        val resultUrl: String? = null,
        val stateJws: String? = null
    )

    private fun post(path: String, body: String): String {
        val connection = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 30_000
            readTimeout = 30_000
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "*/*")
        }
        try {
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            if (code !in 200..299) throw IOException("HTTP $code from $path: $text")
            return text
        } finally {
            connection.disconnect()
        }
    }
}
