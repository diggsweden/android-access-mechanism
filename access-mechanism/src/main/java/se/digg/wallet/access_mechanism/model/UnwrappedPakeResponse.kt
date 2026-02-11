// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

internal data class UnwrappedPakeResponse(
    val response: ByteArray?, val status: Status, val sessionId: String?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnwrappedPakeResponse) return false

        if (!response.contentEquals(other.response)) return false
        if (status != other.status) return false
        if (sessionId != other.sessionId) return false

        return true
    }

    override fun hashCode(): Int {
        var result = response?.contentHashCode() ?: 0
        result = 31 * result + status.hashCode()
        result = 31 * result + (sessionId?.hashCode() ?: 0)
        return result
    }
}
