#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "cJSON.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#include "secrets/config.h"

static const char *TAG = "OTA_APP";

// --- WiFi Connection state flag ---
static bool s_wifi_connected = false;

// --- Forward Declarations ---
void ota_task(void *pvParameter);
void checkForUpdates();
esp_err_t performSecureUpdate(const char* firmwareUrl, const char* signatureUrl);
bool verify_signature(uint8_t* sha256_hash, uint8_t* signature, size_t sig_len);
int compareVersionStrings(const char* v1, const char* v2);
void connectWiFi();

// --- WiFi Event Handler ---
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_wifi_connected = false;
        ESP_LOGI(TAG, "WiFi disconnected, trying to reconnect...");
        vTaskDelay(pdMS_TO_TICKS(5000));
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "WiFi connected! IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_wifi_connected = true;
    }
}

// --- Main Application Entry Point ---
extern "C" void app_main(void) {
    ESP_LOGI(TAG, "Booting Secure OTA Client (ESP-IDF)...");
    ESP_LOGI(TAG, "Current Firmware Version: %s", FIRMWARE_VERSION);

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    connectWiFi();

    xTaskCreate(&ota_task, "ota_task", 8192, NULL, 5, NULL);
}

// --- Main Task (replaces loop()) ---
void ota_task(void *pvParameter) {
    TickType_t lastUpdateCheck = 0;
    TickType_t lastPrint = 0;

    // Wait for the initial WiFi connection
    ESP_LOGI(TAG, "ota_task waiting for WiFi connection...");
    while(!s_wifi_connected) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    ESP_LOGI(TAG, "ota_task detected WiFi connection. Starting main loop.");

    checkForUpdates(); // Initial check

    while (1) {
        TickType_t currentTicks = xTaskGetTickCount();

        if (currentTicks - lastUpdateCheck > pdMS_TO_TICKS(UPDATE_CHECK_INTERVAL_MS)) {
            lastUpdateCheck = currentTicks;
            ESP_LOGI(TAG, "--------------------");
            ESP_LOGI(TAG, "Checking for a new firmware version...");
            if(s_wifi_connected) {
                checkForUpdates();
            } else {
                ESP_LOGW(TAG, "Skipped update check: WiFi is not connected.");
            }
        }

        if (currentTicks - lastPrint > pdMS_TO_TICKS(VERSION_PRINT_INTERVAL_MS)) {
            lastPrint = currentTicks;
            ESP_LOGI(TAG, "Status: Alive. Running firmware version: %s", FIRMWARE_VERSION);
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// --- OTA Logic ---
void checkForUpdates() {
    // Zero-initialize the config struct to avoid compiler warnings
    esp_http_client_config_t config = {};
    config.url = MANIFEST_URL;
    config.cert_pem = GITHUB_ROOT_CA_CERT;
    config.timeout_ms = 10000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "User-Agent", "ESP32-OTA-Client/1.0");
    
    char response_buffer[512] = {0}; // Buffer for manifest content
    esp_http_client_set_post_field(client, NULL, 0); // Force GET request

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return;
    }
    int content_length = esp_http_client_fetch_headers(client);
    int status_code = esp_http_client_get_status_code(client);

    if (status_code != 200) {
        ESP_LOGE(TAG, "Failed to fetch manifest. HTTP Code: %d", status_code);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return;
    }

    int read_len = esp_http_client_read(client, response_buffer, sizeof(response_buffer)-1);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    
    cJSON *json = cJSON_Parse(response_buffer);
    if (json == NULL) {
        ESP_LOGE(TAG, "Failed to parse manifest JSON.");
        return;
    }

    const cJSON *version_item = cJSON_GetObjectItem(json, "version");
    const cJSON *file_url_item = cJSON_GetObjectItem(json, "file_url");
    const cJSON *sig_url_item = cJSON_GetObjectItem(json, "signature_url");

    if (cJSON_IsString(version_item) && cJSON_IsString(file_url_item) && cJSON_IsString(sig_url_item)) {
        char* newVersion = version_item->valuestring;
        if(newVersion[0] == 'v') newVersion++;

        ESP_LOGI(TAG, "Update Check: Current=%s, Available=%s", FIRMWARE_VERSION, newVersion);
        if (compareVersionStrings(newVersion, FIRMWARE_VERSION) > 0) {
            ESP_LOGI(TAG, "New version found. Starting update.");
            performSecureUpdate(file_url_item->valuestring, sig_url_item->valuestring);
        } else {
            ESP_LOGI(TAG, "No new version available.");
        }
    } else {
        ESP_LOGE(TAG, "Manifest is missing required fields.");
    }
    cJSON_Delete(json);
}

// The performSecureUpdate, verify_signature, etc. functions would go here,
// written in pure ESP-IDF style. For now, let's confirm this part compiles.
esp_err_t performSecureUpdate(const char* firmwareUrl, const char* signatureUrl) {
    // Zero-initialize the config struct
    esp_http_client_config_t config = {};
    config.url = firmwareUrl;
    config.cert_pem = GITHUB_ROOT_CA_CERT; // Use the Root CA for security
    config.timeout_ms = 15000;
    config.keep_alive_enable = true;
    
    // The esp_https_ota_perform function is a high-level API that handles redirects,
    // but it doesn't allow for our custom signature check. We must do it manually.

    // Step 1: Get the update partition
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Failed to get update partition.");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);

    esp_ota_handle_t update_handle = 0;
    esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        return err;
    }

    // Step 2: Download firmware, write to partition, and hash simultaneously
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "User-Agent", "ESP32-OTA-Client/1.0");
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        esp_ota_abort(update_handle);
        return err;
    }
    esp_http_client_fetch_headers(client);

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);

    ESP_LOGI(TAG, "Downloading new firmware...");
    char buffer[1024];
    int total_read = 0;
    while (1) {
        int data_read = esp_http_client_read(client, buffer, sizeof(buffer));
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            break;
        }
        if (data_read == 0) {
            break; // Download complete
        }
        
        // Write chunk to OTA partition
        err = esp_ota_write(update_handle, (const void *)buffer, data_read);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
            break;
        }

        // Add chunk to hash
        mbedtls_sha256_update(&sha_ctx, (const unsigned char*)buffer, data_read);
        total_read += data_read;
    }
    esp_http_client_cleanup(client);

    uint8_t sha_result[32];
    mbedtls_sha256_finish(&sha_ctx, sha_result);
    mbedtls_sha256_free(&sha_ctx);

    // Step 3: Download signature
    config.url = signatureUrl;
    client = esp_http_client_init(&config);
    uint8_t signature[256];
    size_t sig_len = 0;
    err = esp_http_client_open(client, 0);
    if (err == ESP_OK) {
        esp_http_client_fetch_headers(client);
        sig_len = esp_http_client_read(client, (char*)signature, sizeof(signature));
    }
    esp_http_client_cleanup(client);
    
    // Step 4: Verify signature
    if (!verify_signature(sha_result, signature, sig_len)) {
        ESP_LOGE(TAG, "SIGNATURE VERIFICATION FAILED! Aborting update.");
        esp_ota_abort(update_handle);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Signature verified successfully!");

    // Step 5: Finalize update
    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        return err;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "UPDATE SUCCESSFUL! Rebooting...");
    esp_restart();

    return ESP_OK; // This line will not be reached
}

// --- Helper Functions ---
bool verify_signature(uint8_t* sha256_hash, uint8_t* signature, size_t sig_len) { /* ... same as before ... */ return false; }
int compareVersionStrings(const char* v1, const char* v2) {
    // Basic C-string implementation
    long part1, part2;
    while (*v1 && *v2) {
        part1 = strtol(v1, (char**)&v1, 10);
        part2 = strtol(v2, (char**)&v2, 10);
        if (part1 > part2) return 1;
        if (part1 < part2) return -1;
        if (*v1 == '.') v1++;
        if (*v2 == '.') v2++;
    }
    if (*v1) return 1; // v1 is longer
    if (*v2) return -1; // v2 is longer
    return 0;
}

void connectWiFi() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
    wifi_config_t wifi_config = {};
    strcpy((char*)wifi_config.sta.ssid, WIFI_SSID);
    strcpy((char*)wifi_config.sta.password, WIFI_PASSWORD);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "WiFi initialization finished.");
}