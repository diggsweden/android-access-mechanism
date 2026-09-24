package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.JwkSerializer

@Serializable
data class KeyResponse(
    @SerialName("public_key") @Serializable(with = JwkSerializer::class) val publicKey: JWK
)




