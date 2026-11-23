plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.rillane.rillane"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.rillane.rillane"
        minSdk = 24
        // demo 面 targetSdk 33：VPN 服务运行期即可完成一轮流量验收；
        // Android 14+ 前台服务类型/通知权限样板与后台常驻面归正式客户端
        // 批次（见 platforms/android/README.md 边界）
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

    buildFeatures {
        viewBinding = true
    }

    // Rust 产物（app/src/main/jniLibs/<abi>/librillane_ffi.so）由 build.sh 预置，
    // gradle 只做打包，不依赖 NDK（无 externalNativeBuild）
}

dependencies {
    // RIL-150 四 Tab Material 3 UI：版本与 AGP 8.7.3 / compileSdk 35 /
    // minSdk 24 兼容面（Material 组件 + Fragment + RecyclerView）
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("com.google.android.material:material:1.12.0")
}
