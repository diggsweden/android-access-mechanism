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
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
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

// Task to extract the Uniffi AAR
val extractUniffi by tasks.registering(Copy::class) {
    from(zipTree("libs/opaque_ke_uniffi-release.aar"))
    into(layout.buildDirectory.dir("uniffi-extracted"))
}

// Ensure extraction happens before build starts
tasks.named("preBuild") {
    dependsOn(extractUniffi)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "se.digg.wallet"
            artifactId = "access-mechanism"
            version = "0.0.2"

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