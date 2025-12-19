package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.AppJson

@Serializable
internal data class InnerRequest(
    val type: String,
    @SerialName("request_counter") val requestCounter: Int,
    val data: String,
    val version: Int = 1
) {
    companion object

    fun toByteArray(): ByteArray {
        return AppJson.encodeToString(this).toByteArray()
    }
}
