package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.Base64ByteArraySerializer

@Serializable
internal data class PakeRequest(
    val task: String? = null,
    @Serializable(with = Base64ByteArraySerializer::class) val authorization: ByteArray? = null,
    @Serializable(with = Base64ByteArraySerializer::class) val data: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PakeRequest) return false

        if (task != other.task) return false
        if (!authorization.contentEquals(other.authorization)) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = task?.hashCode() ?: 0
        result = 31 * result + (authorization?.contentHashCode() ?: 0)
        result = 31 * result + data.contentHashCode()
        return result
    }

}
