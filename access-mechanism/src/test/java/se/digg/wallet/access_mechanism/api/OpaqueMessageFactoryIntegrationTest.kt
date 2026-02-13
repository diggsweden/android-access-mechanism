// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.*
import se.digg.wallet.access_mechanism.model.Operation.AUTHENTICATE_START
import se.digg.wallet.access_mechanism.security.OpaqueCryptoManager
import se.digg.wallet.access_mechanism.utils.AppJson
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Duration

class OpaqueMessageFactoryIntegrationTest {

    private lateinit var cryptoManager: OpaqueCryptoManager
    private lateinit var factory: MessageFactory
    private lateinit var responseProcessor: ResponseProcessor
    private lateinit var clientKeyPair: KeyPair
    private lateinit var serverKeyPair: KeyPair
    private lateinit var dummyKeyPair: KeyPair


    @Before
    fun setup() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))

        clientKeyPair = keyPairGenerator.generateKeyPair()
        serverKeyPair = keyPairGenerator.generateKeyPair()
        val pinStretchKey = keyPairGenerator.generateKeyPair().private

        dummyKeyPair = keyPairGenerator.generateKeyPair()

        cryptoManager = OpaqueCryptoManager(
            serverKeyPair.public as ECPublicKey,
            clientKeyPair.private as ECPrivateKey,
            computeThumbprint(clientKeyPair.public as ECPublicKey),
            pinStretchKey
        )

        factory = MessageFactory(cryptoManager)
        responseProcessor = ResponseProcessor(cryptoManager)
    }

    @Test
    fun `createOpaqueRequest returns a valid signed JWS containing encrypted payload`() {
        // arrange
        val requestBytes = "someRequest".toByteArray()

        // act
        val pakeRequest = PakeRequest(data = requestBytes, task = "someTask")
        val outerRequestJws: OuterRequestJws =
            factory.createPakeRequest(AUTHENTICATE_START, pakeRequest, "sessionId")

        // assert
        // verify Signature using Client's Public Key
        val verifier = ECDSAVerifier(clientKeyPair.public as ECPublicKey)
        assertTrue("Signature verification failed", outerRequestJws.unwrap().verify(verifier))

        // inspect the outerRequest
        val outerRequest =
            AppJson.decodeFromString<OuterRequest>(outerRequestJws.unwrap().payload.toString())
        assertEquals("sessionId", outerRequest.sessionId)
        assertEquals(1, outerRequest.version)
        assertEquals("hsm", outerRequest.context)

        // decrypt the inner Payload (RequestData)
        val requestDataJwe = JWEObject.parse(outerRequest.innerJwe)
        val decrypter = ECDHDecrypter(serverKeyPair.private as ECPrivateKey)
        requestDataJwe.decrypt(decrypter)
        val innerRequest = AppJson.decodeFromString<InnerRequest>(requestDataJwe.payload.toString())

        // verify the encrypted payload
        assertEquals(AUTHENTICATE_START.type, innerRequest.type)
        assertEquals(0, innerRequest.requestCounter)

        // verify pakeRequest
        val data = AppJson.decodeFromString<PakeRequest>(innerRequest.data)
        assertEquals(pakeRequest, data)
    }

    @Test
    fun `server response is successfully unwrapped`() {
        // arrange
        val pakeRequest = PakeRequest(data = "someResponse".toByteArray(), task = "someTask")
        val pakeRequestJson = AppJson.encodeToString(pakeRequest)

        val innerResponse = InnerResponse(pakeRequestJson, Duration.ZERO, Status.OK, 1)
        val innerSerialized = AppJson.encodeToString(innerResponse).toByteArray()
        val innerJwe = encryptBytes(innerSerialized)

        val outerResponse = OuterResponse(1, "someSessionId", innerJwe.serialize())
        val outerResponseBytes = AppJson.encodeToString(outerResponse).toByteArray()
        val outerJws = createSignedJws(outerResponseBytes)

        val serverResponse = outerJws.serialize()

        // act
        val unwrappedResponse = responseProcessor.unwrapPakeResponse(serverResponse)

        // assert
        assertArrayEquals(
            "someResponse".toByteArray(), unwrappedResponse.response
        )
        assertEquals("someSessionId", unwrappedResponse.sessionId)
        assertEquals(Status.OK, unwrappedResponse.status)
    }


    @Test
    fun `unwrapping fails if response is not signed by server`() {
        // arrange
        val responseBytes = "someResponse".toByteArray()

        // signing with the wrong key
        val jwsResponse = createSignedJws(responseBytes, dummyKeyPair.private)
        val serverResponse = jwsResponse.serialize()

        // act & assert
        val exception = assertThrows(OpaqueException.CryptoException::class.java) {
            responseProcessor.unwrapPakeResponse(serverResponse)
        }
        assertEquals("Invalid signature", exception.message)
    }

    @Test
    fun `unwrapping fails if response cannot be decrypted`() {
        // arrange
        val innerResponse = InnerResponse(data = "someData", status = Status.OK, version = 1)
        val innerSerialized = AppJson.encodeToString(innerResponse).toByteArray()
        val innerJwe = encryptBytes(innerSerialized, dummyKeyPair.public)

        val outerResponse = OuterResponse(version = 1, innerJwe = innerJwe.serialize())
        val outerResponseBytes = AppJson.encodeToString(outerResponse).toByteArray()
        val outerJws = createSignedJws(outerResponseBytes)

        val serverResponse = outerJws.serialize()

        // act && assert
        val exception = assertThrows(OpaqueException.ProtocolException::class.java) {
            responseProcessor.unwrapPakeResponse(serverResponse)
        }
        assertEquals("Failed to decrypt response", exception.message)
    }

    @Test
    fun `unwrapping fails if inner response status is ERROR`() {
        // arrange
        val innerResponse = InnerResponse(data = null, status = Status.ERROR, version = 1)
        val innerSerialized = AppJson.encodeToString(innerResponse).toByteArray()
        val innerJwe = encryptBytes(innerSerialized)

        val outerResponse = OuterResponse(version = 1, innerJwe = innerJwe.serialize())
        val outerResponseBytes = AppJson.encodeToString(outerResponse).toByteArray()
        val outerJws = createSignedJws(outerResponseBytes)

        val serverResponse = outerJws.serialize()

        // act && assert
        val exception = assertThrows(OpaqueException.ProtocolException::class.java) {
            responseProcessor.unwrapPakeResponse(serverResponse)
        }
        assertEquals("Server response status not OK: ERROR", exception.message)
    }

    fun encryptBytes(payload: ByteArray, publicKey: PublicKey = clientKeyPair.public): JWEObject {
        val jweHeader = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build()
        val jweObject = JWEObject(jweHeader, Payload(payload))
        val encrypter = ECDHEncrypter(publicKey as ECPublicKey)
        jweObject.encrypt(encrypter)
        return jweObject
    }

    fun createSignedJws(
        payload: ByteArray, privateKey: PrivateKey = serverKeyPair.private
    ): JWSObject {
        val jwsHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()
        val jwsObject = JWSObject(jwsHeader, Payload(payload))
        val signer = ECDSASigner(privateKey as ECPrivateKey)
        jwsObject.sign(signer)
        return jwsObject
    }
}
