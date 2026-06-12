// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import java.security.interfaces.ECPublicKey

data class ServerParameters(
    val serverSigningPublicKey: ECPublicKey,
    val serverEncryptionPublicKey: ECPublicKey,
    val opaqueServerId: String,
    val stateId: String,
    val opaqueContext: String = "RPS-Ops"
)
