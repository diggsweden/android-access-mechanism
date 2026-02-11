// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

data class RegistrationStartResult(
    val registrationRequest: String,
    val clientRegistration: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RegistrationStartResult

        if (registrationRequest != other.registrationRequest) return false
        if (!clientRegistration.contentEquals(other.clientRegistration)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = registrationRequest.hashCode()
        result = 31 * result + clientRegistration.contentHashCode()
        return result
    }
}
