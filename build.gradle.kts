// Top-level build file where you can add configuration options common to all sub-projects/modules.
// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}

// Reproducible archives: without these, the AAR embeds per-file timestamps and
// a filesystem-dependent entry order, so two builds of identical source differ
// byte-for-byte. The release pipeline signs artefacts and publishes SLSA
// provenance, both of which are only meaningful if a rebuild reproduces the
// same bytes.
//
// Applied to subprojects, not the root: the AAR is produced by :access-mechanism,
// and a root-level tasks.withType only configures the root project's own tasks.
subprojects {
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}
