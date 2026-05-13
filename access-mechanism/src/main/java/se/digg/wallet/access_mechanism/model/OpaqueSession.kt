// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

internal data class OpaqueSession(
    val sessionKey: ByteArray,
    val pakeSessionId: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OpaqueSession) return false
        if (!sessionKey.contentEquals(other.sessionKey)) return false
        if (pakeSessionId != other.pakeSessionId) return false
        return true
    }

    override fun hashCode(): Int {
        var result = sessionKey.contentHashCode()
        result = 31 * result + pakeSessionId.hashCode()
        return result
    }
}
