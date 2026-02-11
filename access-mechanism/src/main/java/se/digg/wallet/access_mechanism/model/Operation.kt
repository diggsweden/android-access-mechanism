// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.access_mechanism.model

internal enum class Operation(val type: String) {
    REGISTER_START("register_start"),
    REGISTER_FINISH("register_finish"),

    AUTHENTICATE_START("authenticate_start"),
    AUTHENTICATE_FINISH("authenticate_finish"),

    HSM_GENERATE_KEY("hsm_generate_key"),
    HSM_LIST_KEYS("hsm_list_keys"),
    HSM_SIGN("hsm_sign"),
    HSM_DELETE_KEY("hsm_delete_key")
}
