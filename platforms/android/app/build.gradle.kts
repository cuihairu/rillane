plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.seep.seep"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.seep.seep"
        minSdk = 24
        // demo 面 targetSdk 33：免 Android 14+ 前台服务类型/通知权限样板
        //（VPN 服务在应用前台期间运行即可完成一轮流量验收；后台常驻/
        //  FGS 声明归后续正式面，见 platforms/android/README.md 边界）
        targetSdk = 33
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // Rust 产物（app/src/main/jniLibs/<abi>/libseep_ffi.so）由 build.sh 预置，
    // gradle 只做打包，不依赖 NDK（无 externalNativeBuild）
}

// 纯 framework API，零三方依赖
