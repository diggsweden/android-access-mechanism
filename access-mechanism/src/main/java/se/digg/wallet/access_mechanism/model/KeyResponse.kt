package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import se.digg.wallet.access_mechanism.utils.JwkSerializer

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonIgnoreUnknownKeys
data class KeyResponse(
    @SerialName("public_key") @Serializable(with = JwkSerializer::class) val publicKey: JWK
)
