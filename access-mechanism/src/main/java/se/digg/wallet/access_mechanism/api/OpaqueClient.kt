// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

/**
 * @param serverParameters Server parameters (signing/encryption public keys and identifiers),
 * obtained from the device-state response during [create] and persisted for [resume].
 * @param clientSigningKeyPair EC P-256 key pair used to sign outgoing requests. The private key may
 * be an opaque handle to a hardware-backed key (e.g. AndroidKeyStore with PURPOSE_SIGN).
 * @param clientEncryptionKeyPair EC P-256 key pair used to decrypt server responses (ECDH-ES). The
 * private key may be an opaque handle to a hardware-backed key (e.g. AndroidKeyStore with
 * PURPOSE_AGREE_KEY).
 * @param pinStretchPrivateKey EC private key used for PIN stretching (key agreement only).
 */
class OpaqueClient private constructor(
    val serverParameters: ServerParameters,
    clientSigningKeyPair: KeyPair,
    clientEncryptionKeyPair: KeyPair,
    pinStretchPrivateKey: PrivateKey,
    private val transport: OpaqueTransport,
    private var devAuthorizationCode: String? = null,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    private val cryptoManager = OpaqueCryptoManager(
        serverSigningPublicKey = serverParameters.serverSigningPublicKey,
        serverEncryptionPublicKey = serverParameters.serverEncryptionPublicKey,
        clientSigningKeyPair = clientSigningKeyPair,
        clientEncryptionKeyPair = clientEncryptionKeyPair,
        pinStretchPrivateKey = pinStretchPrivateKey
    )
    private val messageFactory = MessageFactory(cryptoManager)
    private val responseProcessor = ResponseProcessor(cryptoManager)
    private val opaqueClientId: String = cryptoManager.clientKeyThumbprint
    private val serverIdentifier: String = serverParameters.opaqueServerId
    val clientId: String = serverParameters.stateId
    private val opaqueContext: String = serverParameters.opaqueContext
    private var session: OpaqueSession? = null

    companion object {
        /**
         * Creates an [OpaqueClient] by registering the device with the server.
         * Fetches server parameters from the state response automatically.
         * The returned client is ready to call [registration] immediately.
         */
        suspend fun create(
            clientSigningKeyPair: KeyPair,
            clientEncryptionKeyPair: KeyPair,
            pinStretchPrivateKey: PrivateKey,
            transport: OpaqueTransport,
            opaqueContext: String = "RPS-Ops",
            ttl: String? = null,
            overwrite: Boolean = false,
            dispatcher: CoroutineDispatcher = Dispatchers.IO
        ): OpaqueClient = withContext(dispatcher) {
            val state = transport.registerState(
                signingPublicKey = clientSigningKeyPair.public as ECPublicKey,
                encryptionPublicKey = clientEncryptionKeyPair.public as ECPublicKey,
                overwrite = overwrite,
                ttl = ttl
            )
            val serverSigningPublicKey =
                requireNotNull(state.serverJwsPublicKey) { "serverJwsPublicKey missing in state response" }
                    .toECKey().toECPublicKey()
            val serverEncryptionPublicKey =
                requireNotNull(state.serverJwePublicKey) { "serverJwePublicKey missing in state response" }
                    .toECKey().toECPublicKey()
            val serverParameters = ServerParameters(
                serverSigningPublicKey = serverSigningPublicKey,
                serverEncryptionPublicKey = serverEncryptionPublicKey,
                opaqueServerId = state.opaqueServerId,
                stateId = state.clientId,
                opaqueContext = opaqueContext
            )
            OpaqueClient(
                serverParameters = serverParameters,
                clientSigningKeyPair = clientSigningKeyPair,
                clientEncryptionKeyPair = clientEncryptionKeyPair,
                pinStretchPrivateKey = pinStretchPrivateKey,
                transport = transport,
                devAuthorizationCode = state.devAuthorizationCode,
                dispatcher = dispatcher
            )
        }

        /**
         * Reconstructs an [OpaqueClient] from persisted state without a network call.
         * Use this on subsequent app launches after the device has already been registered via [create].
         *
         * The caller is responsible for loading [clientSigningKeyPair], [clientEncryptionKeyPair]
         * and [pinStretchPrivateKey] from the Android Keystore using the key tags that were stored
         * during [create].
         */
        fun resume(
            transport: OpaqueTransport,
            serverParameters: ServerParameters,
            clientSigningKeyPair: KeyPair,
            clientEncryptionKeyPair: KeyPair,
            pinStretchPrivateKey: PrivateKey,
            dispatcher: CoroutineDispatcher = Dispatchers.IO
        ): OpaqueClient = OpaqueClient(
            serverParameters = serverParameters,
            clientSigningKeyPair = clientSigningKeyPair,
            clientEncryptionKeyPair = clientEncryptionKeyPair,
            pinStretchPrivateKey = pinStretchPrivateKey,
            transport = transport,
            devAuthorizationCode = null,
            dispatcher = dispatcher
        )
    }

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
    suspend fun registration(pin: String, stateJws: String? = null): ByteArray =
        withContext(dispatcher) {
            val authCode = requireNotNull(devAuthorizationCode) {
                "No authorization code available — client must be created via OpaqueClient.create()"
            }
            devAuthorizationCode = null
            val start = registrationStart(pin, authCode)
            val startResponse = transport.perform(
                HSMRequest(clientId, start.registrationRequest, stateJws),
                HSMOperationType.REGISTER_PIN
            )
            val finish = registrationFinish(pin, authCode, startResponse, start.clientRegistration)
            val finishResponse = transport.perform(
                HSMRequest(clientId, finish.registrationUpload, stateJws),
                HSMOperationType.REGISTER_PIN
            )
            responseProcessor.unwrapPakeResponse(finishResponse)
            finish.exportKey
        }

    /**
     * Authenticates with the server using the registered PIN. Orchestrates the two-phase
     * OPAQUE login protocol internally and stores the resulting session for subsequent operations.
     *
     * @param pin The user's raw PIN.
     * @param task Optional task label for the session. Defaults to "general".
     * @return The OPAQUE export key derived from authentication.
     */
    suspend fun authenticate(
        pin: String,
        task: String = "general",
        stateJws: String? = null
    ): ByteArray = withContext(dispatcher) {
        val start = loginStart(pin)
        val startResponse = transport.perform(
            HSMRequest(clientId, start.loginRequest, stateJws),
            HSMOperationType.CREATE_SESSION
        )
        val finish = loginFinish(pin, startResponse, start.clientRegistration, task)
        val finishResponse = transport.perform(
            HSMRequest(clientId, finish.loginFinishRequest, stateJws),
            HSMOperationType.CREATE_SESSION
        )
        responseProcessor.unwrapPakeResponse(finishResponse)
        session = OpaqueSession(finish.sessionKey, finish.pakeSessionId)
        finish.exportKey
    }

    /**
     * Changes the registered PIN. Requires an active session from [authenticate].
     * Orchestrates the two-phase OPAQUE re-registration protocol internally.
     *
     * @param newPin The user's new raw PIN.
     * @return The OPAQUE export key derived from the new PIN registration.
     */
    suspend fun changePin(newPin: String, stateJws: String? = null): ByteArray =
        withContext(dispatcher) {
            val (sessionKey, pakeSessionId) = requireSession()
            val start = changePinStart(newPin, sessionKey, pakeSessionId)
            val startResponse = transport.perform(
                HSMRequest(clientId, start.registrationRequest, stateJws),
                HSMOperationType.CHANGE_PIN
            )
            val finish = changePinFinish(
                newPin,
                startResponse,
                start.clientRegistration,
                sessionKey,
                pakeSessionId
            )
            val finishResponse = transport.perform(
                HSMRequest(clientId, finish.registrationUpload, stateJws),
                HSMOperationType.CHANGE_PIN
            )
            responseProcessor.unwrapResponse(finishResponse, sessionKey)
            finish.exportKey
        }

    /**
     * Generates a new P-256 HSM key on the server.
     *
     * @return The decrypted JSON response from the server containing the key details.
     */
    suspend fun createHsmKey(stateJws: String? = null): String = withContext(dispatcher) {
        val (sessionKey, pakeSessionId) = requireSession()
        val innerRequestData = AppJson.encodeToString(mapOf("curve" to "P-256"))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_GENERATE_KEY
        )
        val response = transport.perform(
            HSMRequest(clientId, request.serialize(), stateJws),
            HSMOperationType.CREATE_KEY
        )
        responseProcessor.unwrapResponse(response, sessionKey).response
    }

    /**
     * Lists all HSM keys available on the server for this client.
     *
     * @return A list of [KeyInfo] describing available HSM keys.
     */
    suspend fun listHsmKeys(stateJws: String? = null): List<KeyInfo> = withContext(dispatcher) {
        val (sessionKey, pakeSessionId) = requireSession()
        val innerRequestData = AppJson.encodeToString(mapOf("curves" to listOf<String>()))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_LIST_KEYS
        )
        val response = transport.perform(
            HSMRequest(clientId, request.serialize(), stateJws),
            HSMOperationType.LIST_KEYS
        )
        val json = responseProcessor.unwrapResponse(response, sessionKey).response
        val map = AppJson.decodeFromString<Map<String, List<KeyInfo>>>(json)
        checkNotNull(map["key_info"]) { "key_info is missing in response" }
    }

    /**
     * Deletes an HSM key from the server.
     *
     * @param kid The key ID of the HSM key to delete.
     */
    suspend fun deleteHsmKey(kid: String, stateJws: String? = null) {
        withContext(dispatcher) {
            val (sessionKey, pakeSessionId) = requireSession()
            validateInput(kid.isNotBlank(), "kid cannot be blank")
            val innerRequestData = AppJson.encodeToString(mapOf("hsm_kid" to kid))
            val request = messageFactory.createSessionEncryptedRequest(
                sessionKey, pakeSessionId, innerRequestData, HSM_DELETE_KEY
            )
            transport.perform(
                HSMRequest(clientId, request.serialize(), stateJws),
                HSMOperationType.DELETE_KEY
            )
        }
    }

    /**
     * Signs [data] using the specified HSM key. SHA-256 is computed internally;
     * callers pass raw bytes.
     *
     * @param kid The key ID of the HSM key to sign with.
     * @param data The raw bytes to sign.
     * @return A [SignatureResponse] containing the P1363-encoded signature.
     */
    suspend fun sign(kid: String, data: ByteArray, stateJws: String? = null): SignatureResponse =
        withContext(dispatcher) {
            validateInput(kid.isNotBlank(), "kid cannot be blank")
            val digest = MessageDigest.getInstance("SHA-256").digest(data)
            SignatureResponse(signDigest(kid, digest, stateJws))
        }

    /**
     * Signs [payload] using the specified HSM key and verifies the returned signature
     * against [publicHsmKey].
     *
     * @param kid The key ID of the HSM key to sign with.
     * @param payload The payload to sign.
     * @param curve The signing curve. Defaults to P-256.
     * @param publicHsmKey The HSM key's public key, used to verify the returned signature.
     * @return A compact serialized JWS containing the verified signature.
     */
    suspend fun signJws(
        kid: String,
        payload: String,
        curve: String = "P-256",
        publicHsmKey: JWK,
        stateJws: String? = null
    ): String = withContext(dispatcher) {
        validateInput(kid.isNotBlank(), "kid cannot be blank")
        validateInput(payload.isNotBlank(), "payload cannot be blank")

        val curveInfo = CurveInfo.fromName(curve)
        val jwsObject = JWSObject(
            JWSHeader.Builder(curveInfo.jwsAlgorithm).keyID(kid).build(), Payload(payload)
        )
        val tbsHash =
            MessageDigest.getInstance(curveInfo.digestAlgorithm).digest(jwsObject.signingInput)
        val signatureValue = signDigest(kid, tbsHash, stateJws)

        val signedJwsObject = JWSObject(
            jwsObject.header.toBase64URL(),
            jwsObject.payload.toBase64URL(),
            Base64URL.from(signatureValue)
        )
        cryptoManager.verifyHsmSignature(signedJwsObject, publicHsmKey.toECKey().toECPublicKey())
        signedJwsObject.serialize()
    }

    /**
     * Sends a precomputed [digest] to the HSM for ECDSA signing under key [kid] and returns the
     * raw signature value (base64url-encoded P1363 R‖S). Shared by [sign] and [signJws], which
     * differ only in how they derive the digest and what they do with the result. Requires an
     * active session.
     */
    private suspend fun signDigest(kid: String, digest: ByteArray, stateJws: String?): String {
        val (sessionKey, pakeSessionId) = requireSession()
        val innerRequestData = AppJson.encodeToString(SignRequestPayload(kid, digest))
        val request = messageFactory.createSessionEncryptedRequest(
            sessionKey, pakeSessionId, innerRequestData, HSM_SIGN
        )
        val response = transport.perform(
            HSMRequest(clientId, request.serialize(), stateJws),
            HSMOperationType.SIGN
        )
        val responseData = responseProcessor.unwrapResponse(response, sessionKey).response
        return AppJson.decodeFromString<Map<String, String>>(responseData)["signature"]
            ?: throw OpaqueException.ProtocolException("Missing signature in response")
    }

    // --- Private protocol implementation ---

    private fun requireSession(): OpaqueSession =
        checkNotNull(session) { "No active session — call authenticate() first" }

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
                opaqueClientId.toByteArray(),
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
        pin: String, loginResponse: String, clientRegistration: ByteArray, task: String
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
                opaqueClientId.toByteArray(),
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
        newPin: String, sessionKey: ByteArray, pakeSessionId: String
    ): RegistrationStartResult {
        validateInput(newPin.isNotEmpty(), "PIN cannot be empty")

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

        val decryptedResponse = responseProcessor.unwrapResponse(registrationResponse, sessionKey)
        val response = checkNotNull(
            AppJson.decodeFromString<PakeResponse>(decryptedResponse.response).data
        ) { "registrationResponse data is missing" }

        val finishResult = try {
            clientRegistrationFinish(
                stretchPin(newPin),
                clientRegistration,
                response,
                opaqueClientId.toByteArray(),
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

    private fun stretchPin(pin: String): ByteArray =
        cryptoManager.stretchPin(pin.toByteArray(Charsets.UTF_8))

    private fun validateInput(condition: Boolean, message: String) {
        if (!condition) throw OpaqueException.InvalidInputException(message)
    }
}
