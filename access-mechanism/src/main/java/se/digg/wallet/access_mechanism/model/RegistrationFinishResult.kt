// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

data class RegistrationFinishResult(val registrationUpload: String, val exportKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RegistrationFinishResult

        if (registrationUpload != other.registrationUpload) return false
        if (!exportKey.contentEquals(other.exportKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = registrationUpload.hashCode()
        result = 31 * result + exportKey.contentHashCode()
        return result
    }
}
