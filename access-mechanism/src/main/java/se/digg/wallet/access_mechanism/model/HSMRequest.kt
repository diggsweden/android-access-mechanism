// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import kotlinx.serialization.Serializable

@Serializable
data class HSMRequest(
    val clientId: String,
    val outerRequestJws: String,
    val stateJws: String? = null
)
