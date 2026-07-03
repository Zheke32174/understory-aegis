plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.aegis"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.aegis"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-skeleton"
        resourceConfigurations += listOf("en")
        base.archivesName = "aegis"
    }

    buildTypes {
        debug {
            // Match passgen's posture: even the debug variant is a sideload-
            // installable security tool, so it must not be jdwp-attachable
            // via `adb shell run-as`. Anyone with USB debugging access
            // could otherwise dump TOTP seeds from memory.
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            isMinifyEnabled = false
            isShrinkResources = false
        }
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
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

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    flavorDimensions += "channel"
    productFlavors {
        create("prod") {
            dimension = "channel"
        }
        create("eng") {
            dimension = "channel"
            applicationIdSuffix = ".eng"
            versionNameSuffix = "-eng"
        }
    }
}

dependencies {
    implementation(project(":common-security"))
    implementation(project(":common-backup"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")

    // BiometricPrompt with DEVICE_CREDENTIAL fallback. Same posture as passgen:
    // every launch requires device biometric/PIN to unlock the vault.
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // See passgen/build.gradle.kts for the rationale: override fragment
    // 1.2.5 (transitively pinned by biometric:1.2.0-alpha05) which has
    // the legacy 16-bit requestCode check that breaks
    // rememberLauncherForActivityResult.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    // Fragment is needed because BiometricPrompt requires FragmentActivity.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    // ZXing core for in-process QR decoding from gallery-picked bitmaps.
    // Pure Java, no native deps, no camera dependency. We DO NOT use the
    // android-embedded variant — that pulls camera scanner code we
    // explicitly don't want. Just the decoder.
    implementation("com.google.zxing:core:3.5.3")

    // Robolectric (host-side) for tests that touch JSONObject / Base64 /
    // Uri — Android stubs that don't run on the JVM otherwise. Same
    // posture as the passgen module.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.test.ext:junit:1.2.1")
}
