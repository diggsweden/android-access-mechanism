// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import se.digg.wallet.access_mechanism.utils.JwkSerializer

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonIgnoreUnknownKeys
data class StateResponse(
    val status: String,
    val clientId: String,
    val devAuthorizationCode: String,
    @Serializable(with = JwkSerializer::class) val serverJwsPublicKey: JWK?,
    @Serializable(with = JwkSerializer::class) val serverJwePublicKey: JWK?,
    val opaqueServerId: String,
    val stateJws: String? = null,
)
