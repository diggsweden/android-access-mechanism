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
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.io.encoding.Base64

class OpaqueClient(
    serverPublicKey: ECPublicKey,
    clientKeyPair: KeyPair,
    pinStretchPrivateKey: PrivateKey,
    val serverIdentifier: String,
    val opaqueContext: String,
    private val transport: OpaqueTransport,
    clientId: String? = null
) {
    private val cryptoManager =
        OpaqueCryptoManager(serverPublicKey, clientKeyPair, pinStretchPrivateKey)
    private val messageFactory = MessageFactory(cryptoManager)
    private val responseProcessor = ResponseProcessor(cryptoManager)
    val clientIdentifier: String = clientId ?: cryptoManager.clientKeyThumbprint
    private var devAuthorizationCode: String? = null

    companion object {
        /**
         * Creates an [OpaqueClient] by registering the device with the server.
         * Fetches server public key and server identifier from the state response,
         * so neither needs to be provided by the caller. The returned client is
         * ready to call [registration] immediately — no authorization code handling needed.
         */
        suspend fun create(
            clientKeyPair: KeyPair,
            pinStretchPrivateKey: PrivateKey,
            opaqueContext: String,
            transport: OpaqueTransport,
            overwrite: Boolean = false,
            ttl: String? = null
        ): OpaqueClient {
            val state = transport.registerState(clientKeyPair.public as ECPublicKey, overwrite, ttl)
            val serverPublicKey = requireNotNull(state.serverJwsPublicKey) { "serverJwsPublicKey missing in state response" }
                .toECKey().toECPublicKey()
            val client = OpaqueClient(
                serverPublicKey = serverPublicKey,
                clientKeyPair = clientKeyPair,
                pinStretchPrivateKey = pinStretchPrivateKey,
                serverIdentifier = state.opaqueServerId,
                opaqueContext = opaqueContext,
                transport = transport,
                clientId = state.clientId
            )
            client.devAuthorizationCode = state.devAuthorizationCode
            return client
        }
    }

    // --- Public API ---

    /**
     * Registers a PIN with the server. Orchestrates the two-phase OPAQUE registration
     * protocol internally and returns the derived export key on success.
     *
     * Requires the client to have been created via [create], which stores the one-time
     * authorization code issued by the server. The code is consumed on first call.
     *
     * @param pin The user's raw PIN.
     * @return The OPAQUE export key derived from the registration.
     */
    suspend fun registration(pin: String): ByteArray {
        val authCode = requireNotNull(devAuthorizationCode) {
            "No authorization code available — client must be created via OpaqueClient.create()"
        }
        devAuthorizationCode = null
        val start = registrationStart(pin, authCode)
        val startResponse = transport.registerPin(BFFRequest(clientIdentifier, start.registrationRequest))
        val finish = registrationFinish(pin, authCode, startResponse, start.clientRegistration)
        transport.registerPin(BFFRequest(clientIdentifier, finish.registrationUpload))
        return finish.exportKey
    }

    /**
     * Authenticates with the server using the registered PIN. Orchestrates the two-phase
     * OPAQUE login protocol internally.
     *
     * @param pin The user's raw PIN.
     * @param task Optional task label for the session. Defaults to "general".
     * @return An [AuthenticationResult] containing the session key, session ID, and export key.
     */
    suspend fun authenticate(pin: String, task: String = "general"): AuthenticationResult {
        val start = loginStart(pin)
        val startResponse = transport.createSession(BFFRequest(clientIdentifier, start.loginRequest))
        val finish = loginFinish(pin, startResponse, start.clientRegistration, task)
        transport.createSession(BFFRequest(clientIdentifier, finish.loginFinishRequest))
        return AuthenticationResult(finish.sessionKey, finish.pakeSessionId, finish.exportKey)
    }

    /**
     * Changes the registered PIN. Requires an active session obtained from [authenticate].
     * Orchestrates the two-phase OPAQUE re-registration protocol internally.
     *
     * @param newPin The user's new raw PIN.
     * @param sessionKey The session key from [authenticate].
     * @param pakeSessionId The session ID from [authenticate].
     * @return The OPAQUE export key derived from the new PIN registration.
     */
    suspend fun changePin(newPin: String, sessionKey: ByteArray, pakeSessionId: String): ByteArray {
        val start = changePinStart(newPin, sessionKey, pakeSessionId)
        val startResponse = transport.changePin(BFFRequest(clientIdentifier, start.registrationRequest))
        val finish = changePinFinish(newPin, startResponse, start.clientRegistration, sessionKey, pakeSessionId)
        transport.changePin(BFFRequest(clientIdentifier, finish.registrationUpload))
        return finish.exportKey
    }

    /**
     * Generates a new P-256 HSM key on the server.
     *
     * @param sessionKey The session key from [authenticate].
     * @param pakeSessionId The session ID from [authenticate].
     * @return The decrypted JSON response from the server containing the key details.
     */
    suspend fun createHsmKey(sessionKey: ByteArray, pakeSessionId: String): String {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")

        val innerRequestData = AppJson.encodeToString(mapOf("curve" to "P-256"))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_GENERATE_KEY
        )
        val response = transport.createKey(BFFRequest(clientIdentifier, request.serialize()))
        return responseProcessor.unwrapResponse(response, sessionKey).response
    }

    /**
     * Lists all HSM keys available on the server for this client.
     *
     * @param sessionKey The session key from [authenticate].
     * @param pakeSessionId The session ID from [authenticate].
     * @return A list of [KeyInfo] describing available HSM keys.
     */
    suspend fun listHsmKeys(sessionKey: ByteArray, pakeSessionId: String): List<KeyInfo> {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")

        val innerRequestData = AppJson.encodeToString(mapOf("curves" to listOf<String>()))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_LIST_KEYS
        )
        val response = transport.listKeys(BFFRequest(clientIdentifier, request.serialize()))
        val json = responseProcessor.unwrapResponse(response, sessionKey).response
        val map = AppJson.decodeFromString<Map<String, List<KeyInfo>>>(json)
        return checkNotNull(map["key_info"]) { "key_info is missing in response" }
    }

    /**
     * Deletes an HSM key from the server.
     *
     * @param sessionKey The session key from [authenticate].
     * @param pakeSessionId The session ID from [authenticate].
     * @param kid The key ID of the HSM key to delete.
     */
    suspend fun deleteHsmKey(sessionKey: ByteArray, pakeSessionId: String, kid: String) {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")
        validateInput(kid.isNotBlank(), "kid cannot be blank")

        val innerRequestData = AppJson.encodeToString(mapOf("hsm_kid" to kid))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_DELETE_KEY
        )
        transport.deleteKey(BFFRequest(clientIdentifier, request.serialize()))
    }

    /**
     * Signs [payload] using the specified HSM key and verifies the returned signature
     * against [publicHsmKey].
     *
     * @param sessionKey The session key from [authenticate].
     * @param pakeSessionId The session ID from [authenticate].
     * @param kid The key ID of the HSM key to sign with.
     * @param payload The payload to sign.
     * @param curve The signing curve. Defaults to P-256.
     * @param publicHsmKey The HSM key's public key, used to verify the returned signature.
     * @return A compact serialized JWS containing the verified signature.
     */
    suspend fun signWithHsm(
        sessionKey: ByteArray,
        pakeSessionId: String,
        kid: String,
        payload: String,
        curve: String = "P-256",
        publicHsmKey: JWK
    ): String {
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")
        validateInput(kid.isNotBlank(), "kid cannot be blank")
        validateInput(payload.isNotBlank(), "payload cannot be blank")

        val curveInfo = CurveInfo.fromName(curve)
        val jwsObject = JWSObject(
            JWSHeader.Builder(curveInfo.jwsAlgorithm).keyID(kid).build(), Payload(payload)
        )
        val tbsHash = MessageDigest.getInstance(curveInfo.digestAlgorithm).digest(jwsObject.signingInput)
        val innerRequestData = AppJson.encodeToString(SignRequestPayload(kid, tbsHash))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_SIGN
        )

        val response = transport.sign(BFFRequest(clientIdentifier, request.serialize()))
        val responseData = responseProcessor.unwrapResponse(response, sessionKey).response
        val signatureValue =
            AppJson.decodeFromString<Map<String, String>>(responseData)["signature"]
                ?: throw OpaqueException.ProtocolException("Missing signature in response")

        val signature = transcodeSignature(signatureValue, jwsObject.header.algorithm)
        val signedJwsObject = JWSObject(
            jwsObject.header.toBase64URL(),
            jwsObject.payload.toBase64URL(),
            signature
        )
        cryptoManager.verifyHsmSignature(signedJwsObject, publicHsmKey.toECKey().toECPublicKey())
        return signedJwsObject.serialize()
    }

    // --- Private protocol implementation ---

    private fun registrationStart(pin: String, authorizationCode: String): RegistrationStartResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")
        validateInput(authorizationCode.isNotEmpty(), "authorizationCode cannot be empty")

        val startResult = try {
            clientRegistrationStart(stretchPin(pin))
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native registration failed", e)
        }

        val pakeRequest =
            PakeRequest(authorization = authorizationCode, data = startResult.registrationRequest)
        val request: OuterRequestJws = messageFactory.createPakeRequest(REGISTER_START, pakeRequest)
        return RegistrationStartResult(request.serialize(), startResult.clientRegistration)
    }

    private fun registrationFinish(
        pin: String,
        authorizationCode: String,
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

    private fun loginStart(pin: String): LoginStartResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")

        val startResult = try {
            clientLoginStart(stretchPin(pin))
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native login start failed", e)
        }

        val pakeRequest = PakeRequest(data = startResult.credentialRequest)
        val request: OuterRequestJws =
            messageFactory.createPakeRequest(AUTHENTICATE_START, pakeRequest)
        return LoginStartResult(request.serialize(), startResult.clientRegistration)
    }

    private fun loginFinish(
        pin: String,
        loginResponse: String,
        clientRegistration: ByteArray,
        task: String
    ): LoginFinishResult {
        validateInput(pin.isNotEmpty(), "PIN cannot be empty")
        validateInput(loginResponse.isNotBlank(), "loginResponse cannot be blank")
        validateInput(clientRegistration.isNotEmpty(), "clientRegistration cannot be empty")

        val decryptedResponseData = responseProcessor.unwrapPakeResponse(loginResponse)
        val credentialResponse =
            checkNotNull(decryptedResponseData.response) { "credentialResponse is missing" }
        val sessionId =
            checkNotNull(decryptedResponseData.sessionId) { "sessionId is missing" }

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
        val request: OuterRequestJws =
            messageFactory.createPakeRequest(AUTHENTICATE_FINISH, pakeRequest, sessionId)
        return LoginFinishResult(
            request.serialize(),
            finishResult.sessionKey,
            decryptedResponseData.sessionId,
            finishResult.exportKey
        )
    }

    private fun changePinStart(
        newPin: String,
        sessionKey: ByteArray,
        pakeSessionId: String
    ): RegistrationStartResult {
        validateInput(newPin.isNotEmpty(), "PIN cannot be empty")
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")

        val startResult = try {
            clientRegistrationStart(stretchPin(newPin))
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native registration failed", e)
        }

        val pakeRequest =
            AppJson.encodeToString(PakeRequest(data = startResult.registrationRequest))
        val request: OuterRequestJws = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, pakeRequest, CHANGE_PIN_START
        )
        return RegistrationStartResult(request.serialize(), startResult.clientRegistration)
    }

    private fun changePinFinish(
        newPin: String,
        registrationResponse: String,
        clientRegistration: ByteArray,
        sessionKey: ByteArray,
        pakeSessionId: String
    ): RegistrationFinishResult {
        validateInput(newPin.isNotEmpty(), "PIN cannot be empty")
        validateInput(registrationResponse.isNotBlank(), "registrationResponse cannot be blank")
        validateInput(clientRegistration.isNotEmpty(), "clientRegistration cannot be empty")
        validateInput(sessionKey.isNotEmpty(), "sessionKey cannot be empty")
        validateInput(pakeSessionId.isNotBlank(), "pakeSessionId cannot be blank")

        val decryptedResponse = responseProcessor.unwrapResponse(registrationResponse, sessionKey)
        val response = checkNotNull(
            AppJson.decodeFromString<PakeResponse>(decryptedResponse.response).data
        ) { "registrationResponse data is missing" }

        val finishResult = try {
            clientRegistrationFinish(
                stretchPin(newPin),
                clientRegistration,
                response,
                clientIdentifier.toByteArray(),
                serverIdentifier.toByteArray()
            )
        } catch (e: Exception) {
            throw OpaqueException.CryptoException("Native registration finish failed", e)
        }

        val pakeRequest =
            AppJson.encodeToString(PakeRequest(data = finishResult.registrationUpload))
        val request: OuterRequestJws = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, pakeRequest, CHANGE_PIN_FINISH
        )
        return RegistrationFinishResult(request.serialize(), finishResult.exportKey)
    }

    private fun transcodeSignature(signatureValue: String, algorithm: JWSAlgorithm): Base64URL {
        val derSignature = Base64.decode(signatureValue)
        val curveInfo = CurveInfo.fromAlgorithm(algorithm)
        return Base64URL.encode(ECDSA.transcodeSignatureToConcat(derSignature, curveInfo.length))
    }

    private fun stretchPin(pin: String): ByteArray =
        cryptoManager.stretchPin(pin.toByteArray(Charsets.UTF_8))

    private fun validateInput(condition: Boolean, message: String) {
        if (!condition) throw OpaqueException.InvalidInputException(message)
    }
}
