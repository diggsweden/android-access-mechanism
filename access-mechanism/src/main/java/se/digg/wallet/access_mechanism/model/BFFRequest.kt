// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

data class BFFRequest(
    val clientId: String,
    val outerRequestJws: String
)
