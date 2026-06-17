// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism

import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Test
import se.digg.opaque_ke_uniffi.clientRegistrationStart

/**
 * Canary test: verifies the native UniFFI OPAQUE bindings load and execute on the
 * host JVM — i.e. without an Android device or emulator — using the desktop-native
 * library supplied via `libs/opaque_ke_uniffi-desktop.jar` and the desktop JNA.
 *
 * Skips gracefully if no host-native slice exists for the current platform (e.g. a
 * macOS or Windows machine when only the linux-x86-64 slice has been built), so the
 * unit-test suite never hard-fails purely because a platform binary is missing.
 */
class NativeLibraryLoadsTest {

    @Test
    fun `opaque native library loads and runs on the host jvm`() {
        val result = try {
            clientRegistrationStart("test".toByteArray())
        } catch (e: LinkageError) {
            Assume.assumeNoException(
                "No host-native opaque_ke_uniffi slice loadable on this platform; skipping",
                e
            )
            return
        }

        assertTrue("registrationRequest should not be empty", result.registrationRequest.isNotEmpty())
        assertTrue("clientRegistration should not be empty", result.clientRegistration.isNotEmpty())
    }
}
