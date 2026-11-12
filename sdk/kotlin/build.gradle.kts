import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
}

group = "org.openentity"
version = "0.1.0"

repositories {
    mavenCentral()
}

// JVM 17 bytecode and no toolchain: this Mac builds on JDK 25, CI on JDK 17, and the Android app (min SDK 28) links it.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

tasks.test {
    useJUnit()
    // The shared vectors at the repo root, the same files the TS, Python and Swift SDKs run.
    systemProperty("vectors", rootProject.file("../../test-vectors").absolutePath)
    inputs.dir(rootProject.file("../../test-vectors")) // a vector change reruns the tests
}
