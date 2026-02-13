// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class OuterResponse(
    val version: Int,
    @SerialName("session_id") val sessionId: String? = null,
    @SerialName("inner_jwe") val innerJwe: String
)
