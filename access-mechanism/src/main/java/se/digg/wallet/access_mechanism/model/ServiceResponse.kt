// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.Base64ByteArraySerializer
import se.digg.wallet.access_mechanism.utils.DurationIso8601Serializer
import java.time.Duration

@Serializable
internal data class ServiceResponse(
    val ver: String,
    val nonce: String,
    @SerialName("expires_in")
    @Serializable(with = DurationIso8601Serializer::class)
    val expiresIn: Duration? = null,
    val enc: String,
    @Serializable(with = Base64ByteArraySerializer::class)
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ServiceResponse

        if (ver != other.ver) return false
        if (nonce != other.nonce) return false
        if (expiresIn != other.expiresIn) return false
        if (enc != other.enc) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ver.hashCode()
        result = 31 * result + nonce.hashCode()
        result = 31 * result + expiresIn.hashCode()
        result = 31 * result + enc.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
