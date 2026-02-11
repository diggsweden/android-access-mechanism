// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.Base64ByteArraySerializer

@Serializable
internal data class PakeResponse(
    val task: String?,
    @Serializable(with = Base64ByteArraySerializer::class) val data: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PakeResponse) return false

        if (task != other.task) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = task?.hashCode() ?: 0
        result = 31 * result + (data?.contentHashCode() ?: 0)
        return result
    }
}
