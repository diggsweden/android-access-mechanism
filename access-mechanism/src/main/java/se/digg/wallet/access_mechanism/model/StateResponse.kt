// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.Serializable
import se.digg.wallet.access_mechanism.utils.JwkSerializer

@Serializable
data class StateResponse(
    val status: String,
    val clientId: String,
    val devAuthorizationCode: String,
    @Serializable(with = JwkSerializer::class) val serverJwsPublicKey: JWK?,
    val opaqueServerId: String,
)
