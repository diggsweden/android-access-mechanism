// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

data class LoginFinishResult(
    val loginFinishRequest: String,
    val sessionKey: ByteArray,
    val pakeSessionId: String,
    val exportKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LoginFinishResult

        if (loginFinishRequest != other.loginFinishRequest) return false
        if (!sessionKey.contentEquals(other.sessionKey)) return false
        if (pakeSessionId != other.pakeSessionId) return false
        if (!exportKey.contentEquals(other.exportKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = loginFinishRequest.hashCode()
        result = 31 * result + sessionKey.contentHashCode()
        result = 31 * result + pakeSessionId.hashCode()
        result = 31 * result + exportKey.contentHashCode()
        return result
    }
}
