package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEObject
import kotlinx.serialization.SerializationException
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.*
import se.digg.wallet.access_mechanism.security.OpaqueCryptoManager
import se.digg.wallet.access_mechanism.utils.AppJson

internal class MessageFactory(
    private val cryptoManager: OpaqueCryptoManager
) {

    fun createPakeRequest(
        type: Operation, request: PakeRequest, pakeSessionId: String? = null
    ): OuterRequestJws = try {
        val pakeSessionData = AppJson.encodeToString(request)
        val innerRequest = InnerRequest(type.type, 0, pakeSessionData)

        val innerJwe: JWEObject = cryptoManager.encryptWithPublicKey(innerRequest)
        createOuterRequestJws(innerJwe, pakeSessionId)
    } catch (e: JOSEException) {
        throw OpaqueException.ProtocolException("Failed to construct encrypted request", e)
    } catch (e: SerializationException) {
        throw OpaqueException.ProtocolException("Failed to serialize request", e)
    }

    fun createSessionEncryptedRequest(
        sessionKey: ByteArray, pakeSessionId: String, request: String, type: Operation
    ): OuterRequestJws = try {
        val innerRequest = InnerRequest(type.type, 0, request)
        val innerJwe: JWEObject = cryptoManager.encryptWithSessionKey(innerRequest, sessionKey)
        createOuterRequestJws(innerJwe, pakeSessionId)
    } catch (e: JOSEException) {
        throw OpaqueException.ProtocolException("Failed to construct session encrypted request", e)
    } catch (e: SerializationException) {
        throw OpaqueException.ProtocolException("Failed to serialize session request", e)
    }

    private fun createOuterRequestJws(
        innerJwe: JWEObject, sessionId: String?
    ): OuterRequestJws {
        val outerRequest =
            OuterRequest(version = 1, sessionId = sessionId, innerJwe = innerJwe.serialize())

        val serializedRequest = AppJson.encodeToString(outerRequest).toByteArray()
        val signed = cryptoManager.sign(serializedRequest)
        return OuterRequestJws(signed)
    }
}
