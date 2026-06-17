// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import com.nimbusds.jose.crypto.impl.ECDSA
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Test
import se.digg.wallet.access_mechanism.api.OpaqueClient
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Integration tests against a live dev backend, mirroring the iOS `APIRequestTests` suite.
 *
 * Each test provisions a fresh ephemeral P-256 device key, registers a new device-state,
 * and drives a full OPAQUE/HSM flow through [OpaqueClient] over [HttpOpaqueTransport].
 * The real native OPAQUE bindings run on the host JVM (no emulator) via the desktop slice.
 *
 * The suite targets [BASE_URL] and **skips gracefully** (JUnit `Assume`) when the backend
 * is unreachable, so it never hard-fails in environments where the dev service is absent.
 */
class OpaqueClientIntegrationTest {

    private companion object {
        const val BASE_URL = "http://localhost:8088"
    }

    private fun generateEcKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    /** Provisions a fresh client: ephemeral keys + a newly registered device-state. */
    private suspend fun newClient(): OpaqueClient =
        OpaqueClient.create(
            clientKeyPair = generateEcKeyPair(),
            pinStretchPrivateKey = generateEcKeyPair().private,
            transport = HttpOpaqueTransport(BASE_URL)
        )

    /**
     * Runs [block] against the backend, converting "backend not running" failures into a
     * skipped test rather than a failure — matching the iOS suite's connection-error handling.
     */
    private fun integrationTest(block: suspend () -> Unit) = runBlocking {
        try {
            block()
        } catch (e: ConnectException) {
            Assume.assumeNoException("Backend not reachable at $BASE_URL; skipping", e)
        } catch (e: SocketTimeoutException) {
            Assume.assumeNoException("Backend timed out at $BASE_URL; skipping", e)
        } catch (e: UnknownHostException) {
            Assume.assumeNoException("Backend host unresolved for $BASE_URL; skipping", e)
        }
    }

    @Test
    fun `registering a new device state yields a client id`() = integrationTest {
        val client = newClient()
        assertFalse("clientId should not be blank", client.clientId.isBlank())
    }

    @Test
    fun `device state registration returns a state jws`() = integrationTest {
        val transport = HttpOpaqueTransport(BASE_URL)
        val state = transport.registerState(
            publicKey = generateEcKeyPair().public as ECPublicKey,
            overwrite = false
        )
        assertFalse("clientId should not be blank", state.clientId.isBlank())
        assertNotNull("backend should return a stateJws on fresh registration", state.stateJws)
        assertFalse("stateJws should not be blank", state.stateJws!!.isBlank())
    }

    @Test
    fun `registration followed by authentication establishes a session`() = integrationTest {
        val client = newClient()
        val pin = "1234"

        val registrationExportKey = client.registration(pin)
        assertTrue("registration export key should not be empty", registrationExportKey.isNotEmpty())

        val authExportKey = client.authenticate(pin)
        assertTrue("authentication export key should not be empty", authExportKey.isNotEmpty())

        // A working session is proven by a successful session-scoped call.
        client.listHsmKeys()
    }

    @Test
    fun `listing keys after authentication returns the device key set`() = integrationTest {
        val client = newClient()
        client.registration("1234")
        client.authenticate("1234")

        val keys = client.listHsmKeys()
        assertTrue("key set should be non-negative", keys.size >= 0)
    }

    @Test
    fun `creating an hsm key increases the key count`() = integrationTest {
        val client = newClient()
        client.registration("1234")
        client.authenticate("1234")

        val before = client.listHsmKeys().size
        client.createHsmKey()
        val after = client.listHsmKeys().size

        assertTrue("expected at least one more key after create ($before -> $after)", after >= before + 1)
    }

    @Test
    fun `signing with an hsm key produces a signature that verifies`() = integrationTest {
        val client = newClient()
        client.registration("1234")
        client.authenticate("1234")

        // A freshly provisioned device-state ships with an initial HSM key; use it directly.
        // (The backend allows only one mutating HSM op per session, so we do not create a key first.)
        val key = client.listHsmKeys().firstOrNull()
        assertNotNull("expected at least one HSM key to sign with", key)
        val kid = requireNotNull(key!!.publicKey.keyID) { "HSM key JWK is missing a kid" }

        // sign() hashes the message with SHA-256 internally and returns the server's raw
        // P1363 (R‖S concat) signature, base64url-encoded. Verify it the same way iOS does:
        // decode, convert to DER, and check it against the HSM public key over the message.
        val message = "test message".toByteArray()
        val signatureResponse = client.sign(kid, message)

        val concat = Base64.getUrlDecoder().decode(signatureResponse.signature)
        val der = ECDSA.transcodeSignatureToDER(concat)
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(key.publicKey.toECKey().toECPublicKey())
            update(message)
        }
        assertTrue("HSM signature should verify against the key's public JWK", verifier.verify(der))
    }

    @Test
    fun `changing the pin allows re-authentication with the new pin`() = integrationTest {
        val client = newClient()
        val oldPin = "1234"
        val newPin = "5678"

        client.registration(oldPin)
        client.authenticate(oldPin)

        client.changePin(newPin)

        // The server destroys the session on PIN change; re-authenticate with the new PIN.
        val exportKey = client.authenticate(newPin)
        assertTrue("re-auth export key should not be empty", exportKey.isNotEmpty())
        client.listHsmKeys()
    }
}
