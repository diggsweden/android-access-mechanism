// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

import se.digg.wallet.access_mechanism.model.BFFRequest

interface OpaqueTransport {
    suspend fun registerPin(request: BFFRequest): String
    suspend fun createSession(request: BFFRequest): String
    suspend fun changePin(request: BFFRequest): String
    suspend fun createKey(request: BFFRequest): String
    suspend fun listKeys(request: BFFRequest): String
    suspend fun sign(request: BFFRequest): String
    suspend fun deleteKey(request: BFFRequest)
}
