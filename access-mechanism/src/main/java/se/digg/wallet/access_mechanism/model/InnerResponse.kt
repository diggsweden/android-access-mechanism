package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.DurationIso8601Serializer
import java.time.Duration

@Serializable
internal data class InnerResponse(
    val data: String? = null,
    @SerialName("expires_in") @Serializable(with = DurationIso8601Serializer::class) val expiresIn: Duration? = null,
    val status: Status,
    val version: Int
)
