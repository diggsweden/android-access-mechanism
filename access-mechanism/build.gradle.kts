// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    id("maven-publish")
    signing
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
            withJavadocJar()
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

val githubToken: String = findProperty("githubToken") as String? ?: ""
val githubActor: String = findProperty("githubActor") as String? ?: ""
val mavenCentralUsername: String = findProperty("mavenCentralUsername") as String? ?: ""
val mavenCentralPassword: String = findProperty("mavenCentralPassword") as String? ?: ""
val publishVersion: String = findProperty("VERSION_NAME") as String? ?: "0.0.1-SNAPSHOT"

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "se.digg.wallet"
            artifactId = "access-mechanism"
            version = publishVersion

            afterEvaluate {
                from(components["release"])
            }

            pom {
                name.set("Android Access Mechanism")
                description.set("Android library for wallet access mechanism using OPAQUE key exchange.")
                url.set("https://github.com/diggsweden/android-access-mechanism")

                licenses {
                    license {
                        name.set("EUPL-1.2")
                        url.set("https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12")
                    }
                }
                developers {
                    developer {
                        id.set("ospo-bot")
                        name.set("OSPO Bot")
                        email.set("ospo@digg.se")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/diggsweden/android-access-mechanism.git")
                    developerConnection.set("scm:git:ssh://github.com/diggsweden/android-access-mechanism.git")
                    url.set("https://github.com/diggsweden/android-access-mechanism")
                }
            }
        }
    }

    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/diggsweden/android-access-mechanism")
            credentials {
                username = githubActor
                password = githubToken
            }
        }

        maven {
            name = "MavenCentral"
            val isSnapshot = publishVersion.endsWith("-SNAPSHOT")
            url = uri(
                if (isSnapshot)
                    "https://s01.oss.sonatype.org/content/repositories/snapshots/"
                else
                    "https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"
            )
            credentials {
                username = mavenCentralUsername
                password = mavenCentralPassword
            }
        }
    }
}

val signingKeyId: String = findProperty("signingKeyId") as String? ?: ""
val signingKey: String = findProperty("signingKey") as String? ?: ""
val signingPassword: String = findProperty("signingPassword") as String? ?: ""

signing {
    if (signingKeyId.isNotBlank() && signingKey.isNotBlank()) {
        useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
        sign(publishing.publications["release"])
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.kotlinx.serialization.json)
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
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
