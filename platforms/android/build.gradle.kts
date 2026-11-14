// RILLANE Android demo——根构建脚本
// AGP/Kotlin 版本在此钉死；gradle 发行版由 build.sh 引导（见 platforms/android/build.sh）
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}
