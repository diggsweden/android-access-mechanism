package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.Base64ByteArraySerializer

@Serializable
data class SignRequestPayload(
    @SerialName("hsm_kid")
    private val hsmKid: String,
    @Serializable(with = Base64ByteArraySerializer::class) private val message: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignRequestPayload

        if (hsmKid != other.hsmKid) return false
        if (!message.contentEquals(other.message)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hsmKid.hashCode()
        result = 31 * result + message.contentHashCode()
        return result
    }
}
