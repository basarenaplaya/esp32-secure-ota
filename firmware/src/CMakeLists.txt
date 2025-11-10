cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32-secure-ota-idf)```

#### **`esp32-secure-ota-idf/main/CMakeLists.txt` (Main Component CMake)**

This file tells the build system what your code needs.

```cmake
idf_component_register(SRCS "main.cpp"
                    INCLUDE_DIRS "." "secrets")

target_link_libraries(${COMPONENT_TARGET} "-Wl,--Map=output.map")

set(COMPONENT_REQUIRES
    "cJSON"
    "esp_http_client"
    "esp_https_ota"
    "esp_wifi"
    "esp_event"
    "esp_log"
    "mbedtls"
    "nvs_flash"
)