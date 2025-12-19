package se.digg.wallet.access_mechanism.security

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import se.digg.opaque_ke_uniffi.hashToCurveP256Sha256
import se.digg.wallet.access_mechanism.exception.OpaqueException
import se.digg.wallet.access_mechanism.model.InnerRequest
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec
import java.security.spec.ECPoint as JavaECPoint

internal class OpaqueCryptoManager(
    private val serverPublicKey: ECPublicKey,
    private val clientPrivateKey: ECPrivateKey,
    private val pinStretchPrivateKey: PrivateKey
) {

    /**
     * Creates a signed JWS containing the payload
     */
    fun sign(data: ByteArray): JWSObject {

        // create JWSObject
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()
        val jwsObject = JWSObject(
            header, Payload(data)
        )

        // sign JWS
        val signer = ECDSASigner(clientPrivateKey)
        jwsObject.sign(signer)
        return jwsObject
    }

    /**
     * Encrypts an InnerRequest to a JWE. This is used for opaque requests where the servers' public key is used for encryption.
     */
    fun encryptWithPublicKey(innerRequest: InnerRequest): JWEObject {
        val header =
            JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).keyID("device")
                .build()

        val jweObject = JWEObject(header, Payload(innerRequest.toByteArray()))
        val encrypter = ECDHEncrypter(serverPublicKey)
        jweObject.encrypt(encrypter)
        return jweObject
    }

    /**
     * Encrypts an InnerRequest to a JWE. This is used for all requests where there is already a sessionKey available.
     */
    fun encryptWithSessionKey(innerRequest: InnerRequest, sessionKey: ByteArray): JWEObject {
        val header =
            JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).keyID("session").build()
        val jweObject = JWEObject(header, Payload(innerRequest.toByteArray()))
        val jweEncrypter = DirectEncrypter(SecretKeySpec(sessionKey, "AES"))
        jweObject.encrypt(jweEncrypter)
        return jweObject
    }

    /**
     * Verifies the signature of a JWSObject using the server's public key
     */
    fun verifySignature(jwsObject: JWSObject) {
        val jwsVerifier = ECDSAVerifier(serverPublicKey)
        if (!jwsObject.verify(jwsVerifier)) {
            throw OpaqueException.CryptoException("Invalid signature")
        }
    }

    fun verifyHsmSignature(jwsObject: JWSObject, publicHsmKey: ECPublicKey) {
        val jwsVerifier = ECDSAVerifier(publicHsmKey)
        if (!jwsObject.verify(jwsVerifier)) {
            throw OpaqueException.CryptoException("Invalid signature")
        }
    }

    /**
     * Decrypts a JWE using the client's private key
     */
    fun decrypt(payloadJwe: JWEObject): JWEObject {
        val decrypter = ECDHDecrypter(clientPrivateKey)
        payloadJwe.decrypt(decrypter)
        return payloadJwe
    }

    /**
     * Decrypts a JWE using a sessionKey
     */
    fun decrypt(payloadJwe: JWEObject, sessionKey: ByteArray): JWEObject {
        val encrypter = DirectDecrypter(SecretKeySpec(sessionKey, "AES"))
        payloadJwe.decrypt(encrypter)
        return payloadJwe
    }

    /**
     * Transforms the PIN into a cryptographically strong 32-byte key
     * by hashing it to an elliptic curve point, performing an ECDH key agreement with
     * the client's private key, and finally applying an HKDF. The result is a
     * "seeded PIN" suitable for use in the OPAQUE protocol.
     *
     * @param pin The user's raw PIN as a ByteArray.
     * @return A 32-byte cryptographically stretched and seeded PIN.
     */
    fun stretchPin(pin: ByteArray): ByteArray {
        val curveName = "secp256r1"

        // 1. Hash to Curve (Get compressed bytes)
        val compressedPoint = hashToCurveP256Sha256(
            pin, "SE_EIDAS_WALLET_PIN_HARDENING".toByteArray()
        )

        // 2. Decode Point (Using BC because Java can't handle compressed bytes easily)
        val bcCurve = ECNamedCurveTable.getParameterSpec(curveName)
        val bouncyCastlePoint: ECPoint = bcCurve.curve.decodePoint(compressedPoint)

        // 3. Reconstruct Java Public Key
        val parameterSpec = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec(curveName))
        }.getParameterSpec(ECParameterSpec::class.java)

        val javaPoint = JavaECPoint(
            bouncyCastlePoint.affineXCoord.toBigInteger(),
            bouncyCastlePoint.affineYCoord.toBigInteger()
        )

        val pinPublicKey =
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(javaPoint, parameterSpec))

        // 4. ECDH
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(pinStretchPrivateKey)
        keyAgreement.doPhase(pinPublicKey, true)
        val ikm = keyAgreement.generateSecret()

        // 5. HKDF
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, null, byteArrayOf()))
        val seededPin = ByteArray(32)
        hkdf.generateBytes(seededPin, 0, 32)

        return seededPin
    }

}
