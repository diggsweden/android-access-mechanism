package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSObject
import kotlinx.serialization.SerializationException
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.*
import se.digg.wallet.access_mechanism.security.OpaqueCryptoManager
import se.digg.wallet.access_mechanism.utils.AppJson
import java.text.ParseException

internal class ResponseProcessor(
    private val cryptoManager: OpaqueCryptoManager
) {

    fun unwrapPakeResponse(response: String): UnwrappedPakeResponse {
        val (outerResponse, innerResponse) = parseAndDecrypt(response)

        val pakeResponse: PakeResponse =
            innerResponse.data?.let { AppJson.decodeFromString<PakeResponse>(it) }
                ?: throw OpaqueException.ProtocolException("Missing PAKE response in server response")

        return UnwrappedPakeResponse(
            pakeResponse.data, innerResponse.status, outerResponse.sessionId
        )
    }

    fun unwrapResponse(response: String, sessionKey: ByteArray): UnwrappedJsonResponse {
        val (_, innerResponse) = parseAndDecrypt(response, sessionKey)

        val data = innerResponse.data
            ?: throw OpaqueException.ProtocolException("Missing data in innerResponse")

        return UnwrappedJsonResponse(data, innerResponse.status)
    }

    private fun parseAndDecrypt(
        response: String, sessionKey: ByteArray? = null
    ): Pair<OuterResponse, InnerResponse> = try {
        val serverResponseJws = JWSObject.parse(response)
        cryptoManager.verifySignature(serverResponseJws)

        val outerResponse: OuterResponse =
            AppJson.decodeFromString<OuterResponse>(serverResponseJws.payload.toString())

        val innerJwe = JWEObject.parse(outerResponse.innerJwe)
        val decryptedInner = if (sessionKey != null) {
            cryptoManager.decrypt(innerJwe, sessionKey)
        } else {
            cryptoManager.decrypt(innerJwe)
        }

        val innerResponse: InnerResponse =
            AppJson.decodeFromString<InnerResponse>(decryptedInner.payload.toString())

        if (innerResponse.status != Status.OK) {
            throw OpaqueException.ProtocolException("Server response status not OK: ${innerResponse.status}")
        }

        outerResponse to innerResponse
    } catch (e: JOSEException) {
        throw OpaqueException.ProtocolException("Failed to decrypt response", e)
    } catch (e: ParseException) {
        throw OpaqueException.ProtocolException("Failed to parse response", e)
    } catch (e: SerializationException) {
        throw OpaqueException.ProtocolException("Failed to deserialize response data", e)
    }
}
