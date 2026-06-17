// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    id("maven-publish")
}

android {
    namespace = "se.digg.wallet.access_mechanism"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        minSdk = 29

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    // Fat AAR configuration: Include extracted JNI libs
    sourceSets {
        getByName("main") {
            jniLibs.srcDir(layout.buildDirectory.dir("uniffi-extracted/jni"))
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// Task to extract the Uniffi AAR
val extractUniffi by tasks.registering(Copy::class) {
    from(zipTree("libs/opaque_ke_uniffi-release.aar"))
    into(layout.buildDirectory.dir("uniffi-extracted"))
}

// Ensure extraction happens before the build starts
tasks.named("preBuild") {
    dependsOn(extractUniffi)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "se.digg.wallet"
            artifactId = "access-mechanism"
            version = "0.0.3"

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.kotlinx.serialization.json)
    // api: CoroutineDispatcher appears in the public OpaqueClient API
    api(libs.kotlinx.coroutines.core)
    implementation(libs.bouncy.castle.bcprov)
    api(libs.nimbus.jose.jwt)

    // Fat AAR: Compile against the extracted classes.jar so it gets bundled
    implementation(files(layout.buildDirectory.file("uniffi-extracted/classes.jar")))

    implementation(libs.jna) {
        artifact {
            type = "aar"
        }
    }
    testImplementation(libs.junit)
    // Run the UniFFI OPAQUE bindings on the host JVM (no emulator) in unit tests.
    // The release AAR only ships Android .so files, so the desktop-native slice is
    // supplied separately here, mirroring the macOS slice in the iOS XCFramework.
    // The desktop JNA jar provides the host jnidispatch (the project's main JNA is
    // the Android aar variant, which only carries device binaries).
    //
    // The jar is host-architecture-specific and is not committed (build it with
    // `make desktop` in the opaque_ke_uniffi repo; see README). It carries only
    // native .so resources — no .class files — so omitting it still compiles the
    // tests; the integration tests then Assume-skip at runtime. Only put it on the
    // classpath when present, otherwise Gradle's artifact transform hard-fails on
    // the missing file during configuration.
    val desktopJar = file("libs/opaque_ke_uniffi-desktop.jar")
    if (desktopJar.exists()) {
        testImplementation(files(desktopJar))
        testImplementation("net.java.dev.jna:jna:${libs.versions.jna.get()}")
    }
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
