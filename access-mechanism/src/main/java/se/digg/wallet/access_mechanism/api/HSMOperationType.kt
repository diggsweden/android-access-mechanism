// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.api

enum class HSMOperationType {
    REGISTER_PIN,
    CREATE_SESSION,
    CHANGE_PIN,
    CREATE_KEY,
    LIST_KEYS,
    SIGN,
    DELETE_KEY
}
