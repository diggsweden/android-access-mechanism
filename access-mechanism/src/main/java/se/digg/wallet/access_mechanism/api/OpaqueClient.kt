// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import se.digg.opaque_ke_uniffi.clientLoginFinish
import se.digg.opaque_ke_uniffi.clientLoginStart
import se.digg.opaque_ke_uniffi.clientRegistrationFinish
import se.digg.opaque_ke_uniffi.clientRegistrationStart
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.*
import se.digg.wallet.access_mechanism.model.Operation.*
import se.digg.wallet.access_mechanism.security.OpaqueCryptoManager
import se.digg.wallet.access_mechanism.utils.AppJson
import se.digg.wallet.access_mechanism.utils.CurveInfo
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.io.encoding.Base64

class OpaqueClient internal constructor(
    private val cryptoManager: OpaqueCryptoManager,
    val clientIdentifier: String,
    val serverIdentifier: String,
    val opaqueContext: String,
    private val messageFactory: MessageFactory = MessageFactory(
        cryptoManager
    ),
    private val responseProcessor: ResponseProcessor = ResponseProcessor(cryptoManager)
) {
    constructor(
        serverPublicKey: ECPublicKey,
        clientPrivateKey: ECPrivateKey,
        pinStretchPrivateKey: PrivateKey,
        clientIdentifier: String,
        serverIdentifier: String,
        opaqueContext: String
    ) : this(
        OpaqueCryptoManager(serverPublicKey, clientPrivateKey, pinStretchPrivateKey),
        clientIdentifier,
        serverIdentifier,
        opaqueContext
    )

    /**
     * Starts the pin registration process.
     *
     * @param pin The user's raw PIN as a String.
     * @return A [RegistrationStartResult] containing the registration request and client registration.
     * @throws OpaqueException.InvalidInputException if the PIN is empty.
     * @throws OpaqueException.CryptoException if the native registration call fails.
     * @throws OpaqueException.ProtocolException if request creation or serialization fails.
     */
    fun registrationStart(pin: String): RegistrationStartResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")

        val startResult = try {
            clientRegistrationStart(stretchPin(pin))
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native registration failed", e)
        }

        val pakeRequest = PakeRequest(data = startResult.registrationRequest)
        val request: OuterRequestJws = messageFactory.createPakeRequest(REGISTER_START, pakeRequest)

        return RegistrationStartResult(request.serialize(), startResult.clientRegistration)
    }

    /**
     * Completes the pin registration process on the client side.
     *
     * @param pin The user's raw PIN as a String.
     * @param authorizationCode A code created on the server and passed to the client during onboarding.
     * @param registrationResponse A serialized JWT containing the registration response from the server.
     * @param clientRegistration The client registration from [registrationStart].
     * @return A [RegistrationFinishResult] containing the registration upload request to send to the server and the export key.
     * @throws OpaqueException.InvalidInputException if input is invalid.
     * @throws OpaqueException.CryptoException if the native registration finish fails.
     * @throws OpaqueException.ProtocolException if response unwrapping or request creation fails.
     */
    fun registrationFinish(
        pin: String,
        authorizationCode: ByteArray,
        registrationResponse: String,
        clientRegistration: ByteArray
    ): RegistrationFinishResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")
        validateInput(authorizationCode.isNotEmpty(), "authorizationCode cannot be empty")
        validateInput(registrationResponse.isNotBlank(), "registrationResponse cannot be blank")
        validateInput(clientRegistration.isNotEmpty(), "clientRegistration cannot be empty")

        val decryptedResponse = responseProcessor.unwrapPakeResponse(registrationResponse)
        val response =
            checkNotNull(decryptedResponse.response) { "registrationResponse is missing" }

        val finishResult = try {
            clientRegistrationFinish(
                stretchPin(pin),
                clientRegistration,
                response,
                clientIdentifier.toByteArray(),
                serverIdentifier.toByteArray()
            )
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native registration finish failed", e)
        }

        val pakeRequest =
            PakeRequest(authorization = authorizationCode, data = finishResult.registrationUpload)
        val request: OuterRequestJws =
            messageFactory.createPakeRequest(REGISTER_FINISH, pakeRequest, null)

        return RegistrationFinishResult(request.serialize(), finishResult.exportKey)
    }

    /**
     * Starts the login process.
     *
     * @param pin The user's raw PIN as a String
     * @return A [LoginStartResult] containing the login request and client registration.
     * @throws OpaqueException.InvalidInputException if the PIN is empty.
     * @throws OpaqueException.CryptoException if the native login start fails.
     * @throws OpaqueException.ProtocolException if request creation fails.
     */
    fun loginStart(pin: String): LoginStartResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")

        val startResult = try {
            clientLoginStart(stretchPin(pin))
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native login start failed", e)
        }

        val pakeRequest = PakeRequest(data = startResult.credentialRequest)
        val request: OuterRequestJws = messageFactory.createPakeRequest(
            AUTHENTICATE_START, pakeRequest
        )
        return LoginStartResult(request.serialize(), startResult.clientRegistration)
    }

    /**
     * Completes the login process on the client side.
     *
     * @param pin The user's raw PIN as a String.
     * @param loginResponse A serialized JWT containing the login response from the server.
     * @param clientRegistration The client registration from [loginStart].
     * @param task Optional task for the session. Default is "general".
     * @return A [LoginFinishResult] containing the login finish request to send to the server and the derived session key.
     * @throws OpaqueException.InvalidInputException if input is invalid.
     * @throws OpaqueException.CryptoException if the native login finish fails.
     * @throws OpaqueException.ProtocolException if response unwrapping or request creation fails.
     */
    fun loginFinish(
        pin: String, loginResponse: String, clientRegistration: ByteArray, task: String = "general"
    ): LoginFinishResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")
        validateInput(loginResponse.isNotBlank(), "loginResponse cannot be blank")
        validateInput(clientRegistration.isNotEmpty(), "clientRegistration cannot be empty")

        val decryptedResponseData = responseProcessor.unwrapPakeResponse(loginResponse)
        val credentialResponse =
            checkNotNull(decryptedResponseData.response) { "credentialResponse is missing" }
        val sessionId = checkNotNull(decryptedResponseData.sessionId) { "sessionId is missing" }

        val finishResult = try {
            clientLoginFinish(
                credentialResponse,
                clientRegistration,
                stretchPin(pin),
                opaqueContext.toByteArray(),
                clientIdentifier.toByteArray(),
                serverIdentifier.toByteArray()
            )
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native login finish failed", e)
        }

        val pakeRequest = PakeRequest(task = task, data = finishResult.credentialFinalization)
        val request: OuterRequestJws = messageFactory.createPakeRequest(
            AUTHENTICATE_FINISH, pakeRequest, sessionId
        )

        return LoginFinishResult(
            request.serialize(),
            finishResult.sessionKey,
            decryptedResponseData.sessionId,
            finishResult.exportKey
        )
    }

    /**
     * Creates a request for creating a new HSM key using P-256.
     *
     * @param sessionKey The session key to be used for encryption. SessionKey is the result of [loginFinish].
     * @param pakeSessionId The session ID to be used for encryption. This is the result of [loginFinish].
     * @return A serialized JWT containing the request to create a new HSM key.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun createHsmKey(sessionKey: ByteArray, pakeSessionId: String): String {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")

        val innerRequestData = AppJson.encodeToString(mapOf("curve" to "P-256"))


        return messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_GENERATE_KEY
        ).serialize()
    }

    /**
     * Creates a request to list available HSM keys.
     *
     * @param sessionKey The session key to be used for encryption. SessionKey is the result of [loginFinish].
     * @param pakeSessionId The session ID to be used for encryption. This is the result of [loginFinish].
     * @return A serialized JWT containing the request to list HSM keys.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun listHsmKeys(sessionKey: ByteArray, pakeSessionId: String): String {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")
        val innerRequestData = AppJson.encodeToString(mapOf("curves" to listOf<String>()))

        return messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_LIST_KEYS
        ).serialize()
    }

    /**
     * Creates a request to delete a specific HSM key.
     *
     * @param sessionKey The session key to be used for encryption. SessionKey is the result of [loginFinish].
     * @param pakeSessionId The session ID to be used for encryption. This is the result of [loginFinish].
     * @param kid The kid of the HSM key to be deleted.
     * @return A serialized JWT containing the request to list HSM keys.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun deleteHsmKey(sessionKey: ByteArray, pakeSessionId: String, kid: String): String {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")
        validateInput(kid.isNotBlank(), "kid cannot be blank")
        val innerRequestData = AppJson.encodeToString(mapOf("hsm_kid" to kid))
        return messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_DELETE_KEY
        ).serialize()
    }

    /**
     * Creates a request to sign a payload with a specific HSM key.
     * The returned pendingSignature, together with the response from the server, can be used as input
     * to [decryptSign] to get the complete signed payload.
     *
     * @param sessionKey The session key to be used for encryption. SessionKey is the result of [loginFinish].
     * @param pakeSessionId The session ID to be used for encryption. This is the result of [loginFinish].
     * @param kid The kid of the HSM key to be used for signing.
     * @param payload The payload to be signed.
     * @param curve The curve to be used for signing. The default is P-256.
     * @return A [PendingSignature] containing the server request to sign the payload and local state for decrypting the response.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun signWithHsm(
        sessionKey: ByteArray,
        pakeSessionId: String,
        kid: String,
        payload: String,
        curve: String = "P-256",
    ): PendingSignature {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")
        validateInput(kid.isNotBlank(), "kid cannot be blank")
        validateInput(payload.isNotBlank(), "payload cannot be blank")

        val curveInfo = CurveInfo.fromName(curve)

        val jwsObject = JWSObject(
            JWSHeader.Builder(curveInfo.jwsAlgorithm).keyID(kid).build(), Payload(payload)
        )

        // create a hash of signingInput (header+payload) to be signed by HSM
        val md = MessageDigest.getInstance(curveInfo.digestAlgorithm)
        val tbsHash = md.digest(jwsObject.signingInput)

        val innerRequestData = AppJson.encodeToString(SignRequestPayload(kid, tbsHash))

        val request: OuterRequestJws = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_SIGN
        )
        return PendingSignature(request.serialize(), jwsObject)
    }

    /**
     * Decrypts a server response and creates a complete signed and verified JWS.
     *
     * @param sessionKey The session key to be used for decryption. SessionKey is the result of [loginFinish].
     * @param pendingSignature The signRequest returned by [signWithHsm].
     * @param serverResponse The server response to be decrypted.
     * @return A complete signed JWS.
     * @throws OpaqueException.CryptoException if the signature verification fails.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun decryptSign(
        sessionKey: ByteArray,
        pendingSignature: PendingSignature,
        serverResponse: String,
        publicHsmKey: JWK
    ): String {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(serverResponse.isNotBlank(), "serverResponse cannot be blank")

        val responseData = responseProcessor.unwrapResponse(serverResponse, sessionKey).response
        val signatureValue =
            AppJson.decodeFromString<Map<String, String>>(responseData)["signature"]
                ?: throw OpaqueException.ProtocolException("Missing signature in response")

        val signature =
            transcodeSignature(signatureValue, pendingSignature.jwsObject.header.algorithm)

        val signedJwsObject = JWSObject(
            pendingSignature.jwsObject.header.toBase64URL(),
            pendingSignature.jwsObject.payload.toBase64URL(),
            signature
        )
        cryptoManager.verifyHsmSignature(signedJwsObject, publicHsmKey.toECKey().toECPublicKey())
        return signedJwsObject.serialize()
    }

    private fun transcodeSignature(
        signatureValue: String, algorithm: JWSAlgorithm
    ): Base64URL {
        val derSignature = Base64.decode(signatureValue)
        val curveInfo = CurveInfo.fromAlgorithm(algorithm)
        return Base64URL.encode(ECDSA.transcodeSignatureToConcat(derSignature, curveInfo.length))
    }

    /**
     * Decrypts a message from the server using the clients private key.
     *
     * @param response A serialized JWT from the server.
     * @return The message from the servers' payload.
     * @throws OpaqueException.ProtocolException if the message cannot be decrypted or parsed.
     * @throws OpaqueException.InvalidInputException if the response is blank.
     */
    fun decryptStatus(response: String): String {
        validateInput(response.isNotBlank(), "response cannot be blank")
        return responseProcessor.unwrapPakeResponse(response).status.toString()
    }

    /**
     * Decrypts the payload from the server using the session key.
     *
     * @param response A serialized JWT from the server.
     * @param sessionKey The session key to be used for decryption.
     * @return The decrypted payload from the servers response as JSON.
     * @throws OpaqueException.ProtocolException if the payload cannot be decrypted or parsed.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun decryptPayload(response: String, sessionKey: ByteArray): String {
        validateInput(response.isNotBlank(), "response cannot be blank")
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        return responseProcessor.unwrapResponse(response, sessionKey).response
    }

    /**
     * Decrypts and deserializes the payload from the server using the session key.
     * This is used to get the response from [listHsmKeys]
     *
     * @param response A serialized JWT from the server.
     * @param sessionKey The session key to be used for decryption.
     * @return A list of [KeyInfo].
     * @throws OpaqueException.ProtocolException if the payload cannot be decrypted, parsed, or deserialized.
     * @throws OpaqueException.InvalidInputException if input parameters are invalid.
     */
    fun decryptKeys(response: String, sessionKey: ByteArray): List<KeyInfo> {
        return decryptPayload(response, sessionKey).let {
            val map = AppJson.decodeFromString<Map<String, List<KeyInfo>>>(it)
            checkNotNull(map["key_info"]) { "key_info is missing in response" }
        }
    }

    private fun stretchPin(pin: String): ByteArray =
        cryptoManager.stretchPin(pin.toByteArray(Charsets.UTF_8))

    private fun validateInput(condition: Boolean, message: String) {
        if (!condition) {
            throw OpaqueException.InvalidInputException(message)
        }
    }
}
