val okhttp = "3.12.0"
dependencies {
    implementation("com.squareup.okhttp3:okhttp:$okhttp")
    api("org.yaml:snakeyaml:1.26")
    implementation(platform("org.springframework.boot:spring-boot-dependencies:2.5.0"))
}
