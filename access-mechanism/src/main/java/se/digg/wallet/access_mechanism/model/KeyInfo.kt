// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.InstantIso8601Serializer
import se.digg.wallet.access_mechanism.utils.JwkSerializer
import java.time.Instant

@Serializable
data class KeyInfo(
    @SerialName("created_at") @Serializable(with = InstantIso8601Serializer::class) val createdAt: Instant,
    @SerialName("public_key") @Serializable(with = JwkSerializer::class) val publicKey: JWK
)
