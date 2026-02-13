// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

import com.nimbusds.jose.JWSObject

class PendingSignature internal constructor(
    val request: String,
    internal val jwsObject: JWSObject
)
