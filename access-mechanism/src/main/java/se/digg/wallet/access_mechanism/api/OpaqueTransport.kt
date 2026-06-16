// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import se.digg.wallet.access_mechanism.model.HSMRequest
import se.digg.wallet.access_mechanism.model.StateResponse
import java.security.interfaces.ECPublicKey

interface OpaqueTransport {
    suspend fun registerState(publicKey: ECPublicKey, overwrite: Boolean, ttl: String? = null): StateResponse
    suspend fun perform(request: HSMRequest, operation: HSMOperationType): String
}
