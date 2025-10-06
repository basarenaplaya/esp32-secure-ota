#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "../../secrets/config.h"

// Forward declarations
void checkForUpdates();
void performSecureUpdate(WiFiClientSecure& client, const String& firmwareUrl, const String& signatureUrl);
bool verify_signature(uint8_t* sha256_hash, uint8_t* signature, size_t sig_len);
void handleErrorState(String errorCode);
bool connectWiFi();
int compareVersionStrings(const String& leftVersion, const String& rightVersion);
bool validateConfiguration();

// Global variables
unsigned long previousMillisUpdate = 0;
unsigned long previousMillisPrint = 0;

// ====================================================================================
// SETUP
// ====================================================================================
void setup() {
  Serial.begin(SERIAL_BAUD_RATE);
  Serial.println("\n\nBooting Secure OTA Client...");
  Serial.println("Current Firmware Version: " + String(FIRMWARE_VERSION));

  if (!validateConfiguration()) {
    Serial.println("FATAL: Configuration validation failed!");
    handleErrorState("CONFIG_VALIDATION_FAILED");
    while (true) { delay(1000); } // Halt execution on bad config
  }

  if (!connectWiFi()) {
    Serial.println("Initial WiFi connection failed. Will retry in the main loop.");
  }

  if (WiFi.status() == WL_CONNECTED) {
    checkForUpdates();
  }
}

// ====================================================================================
// MAIN LOOP
// ====================================================================================
void loop() {
  unsigned long currentMillis = millis();

  // Timer 1: Check for updates periodically
  if (currentMillis - previousMillisUpdate >= UPDATE_CHECK_INTERVAL) {
    previousMillisUpdate = currentMillis;
    Serial.println("--------------------");
    Serial.println("Checking for a new firmware version...");

    if (WiFi.status() != WL_CONNECTED) {
      connectWiFi();
    }

    if (WiFi.status() == WL_CONNECTED) {
      checkForUpdates();
    } else {
      Serial.println("Skipped update check: WiFi is not connected.");
    }
  }

  // Timer 2: Print a heartbeat message
  if (currentMillis - previousMillisPrint >= VERSION_PRINT_INTERVAL) {
    previousMillisPrint = currentMillis;
    Serial.println("Status: Alive. Running firmware version: " + String(FIRMWARE_VERSION));
  }
}

// ====================================================================================
// OTA LOGIC
// ====================================================================================

void checkForUpdates() {
  WiFiClientSecure client;
  // If you have SSL issues, add the GitHub Root CA certificate here.
  // client.setCACert(GITHUB_ROOT_CA_CERT);

  HTTPClient http;
  http.begin(client, GITHUB_RELEASES_URL);
  http.addHeader("User-Agent", "ESP32-OTA-Client/1.0");

  int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.println("PROBLEM: Failed to fetch GitHub release. HTTP Code: " + String(httpCode));
    http.end();
    handleErrorState("GITHUB_RELEASE_FETCH_FAILED");
    return;
  }

  StaticJsonDocument<2048> doc;
  DeserializationError error = deserializeJson(doc, http.getStream());
  http.end();

  if (error) {
    Serial.println("PROBLEM: Failed to parse GitHub release JSON. Error: " + String(error.c_str()));
    handleErrorState("GITHUB_RELEASE_PARSE_FAILED");
    return;
  }

  String newVersion = doc["tag_name"].as<String>();
  if (newVersion.isEmpty()) {
    Serial.println("PROBLEM: No tag_name found in GitHub release.");
    handleErrorState("GITHUB_RELEASE_NO_VERSION");
    return;
  }

  String firmwareUrl = "";
  String signatureUrl = "";
  JsonArray assets = doc["assets"];
  for (JsonObject asset : assets) {
    String name = asset["name"].as<String>();
    if (name == "firmware.bin") {
      firmwareUrl = asset["browser_download_url"].as<String>();
    } else if (name == "signature.bin") {
      signatureUrl = asset["browser_download_url"].as<String>();
    }
  }

  if (firmwareUrl.isEmpty() || signatureUrl.isEmpty()) {
    Serial.println("PROBLEM: Required files (firmware.bin or signature.bin) not found in release assets.");
    handleErrorState("GITHUB_RELEASE_MISSING_FILES");
    return;
  }

  if (newVersion.startsWith("v")) {
    newVersion.remove(0, 1);
  }

  Serial.println("Update Check: Current version is " + String(FIRMWARE_VERSION) + ", GitHub release version is " + newVersion);

  if (compareVersionStrings(newVersion, String(FIRMWARE_VERSION)) > 0) {
    Serial.println("Action: New version found. Starting secure update process.");
    // Pass the already created client to the next function to save memory
    performSecureUpdate(client, firmwareUrl, signatureUrl);
  } else {
    Serial.println("Action: No new version available.");
  }
}

// ====================================================================================
// THE FINAL, CORRECTED performSecureUpdate FUNCTION
// ====================================================================================
void performSecureUpdate(WiFiClientSecure& client, const String& firmwareUrl, const String& signatureUrl) {
  HTTPClient http;
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  Serial.println("Downloading firmware from: " + firmwareUrl);
  http.begin(client, firmwareUrl);
  int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.println("PROBLEM: Failed to download firmware file. HTTP Code: " + String(httpCode));
    http.end();
    handleErrorState("FIRMWARE_DOWNLOAD_FAILED");
    return;
  }

  int contentLength = http.getSize();
  if (contentLength <= 0) {
    Serial.println("PROBLEM: Invalid firmware size from server.");
    http.end();
    handleErrorState("INVALID_FIRMWARE_SIZE");
    return;
  }

  if (!Update.begin(contentLength)) {
    Update.printError(Serial);
    http.end();
    handleErrorState("INSUFFICIENT_SPACE");
    return;
  }

  Serial.println("Downloading new firmware... (this may take a moment)");
  WiFiClient* stream = http.getStreamPtr();

  // *** THIS IS THE CORRECT, MEMORY-SAFE IMPLEMENTATION ***
  // It calculates the hash while writing the stream to flash.
  
  // Initialize the SHA-256 context
  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts_ret(&shaCtx, 0); // 0 for SHA-256

  // Use a static buffer to avoid stack overflow. This is critical.
  static uint8_t buffer[1024];
  size_t totalWritten = 0;

  while (totalWritten < (size_t)contentLength) {
    size_t bytesRead = stream->read(buffer, sizeof(buffer));
    if (bytesRead == 0) {
      // Stream ended unexpectedly
      break;
    }
    
    // Write the chunk to the OTA partition
    if (Update.write(buffer, bytesRead) != bytesRead) {
      Update.abort();
      http.end();
      handleErrorState("FIRMWARE_WRITE_ERROR");
      return;
    }
    
    // Add the same chunk to our ongoing hash calculation
    mbedtls_sha256_update_ret(&shaCtx, buffer, bytesRead);
    
    totalWritten += bytesRead;
  }
  
  http.end();

  if (totalWritten != (size_t)contentLength) {
    Serial.println("PROBLEM: Firmware download incomplete. Wrote " + String(totalWritten) + " of " + String(contentLength) + " bytes.");
    Update.abort();
    handleErrorState("FIRMWARE_WRITE_INCOMPLETE");
    return;
  }

  // Finalize the hash calculation
  uint8_t shaResult[32];
  mbedtls_sha256_finish_ret(&shaCtx, shaResult);
  mbedtls_sha256_free(&shaCtx);

  // Now, download the signature (this part is unchanged and correct)
  Serial.println("Downloading signature from: " + signatureUrl);
  http.begin(client, signatureUrl);
  httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Update.abort();
    http.end();
    handleErrorState("SIGNATURE_DOWNLOAD_FAILED");
    return;
  }
  
  uint8_t signature[256];
  int sigLen = http.getStream().readBytes(signature, 256);
  http.end();

  // Verify the signature against the hash we just calculated
  if (!verify_signature(shaResult, signature, sigLen)) {
    Serial.println("PROBLEM: SIGNATURE VERIFICATION FAILED! Major security alert.");
    Update.abort();
    handleErrorState("SIGNATURE_VERIFICATION_FAILED");
    return;
  }
  Serial.println("SIGNATURE VERIFIED SUCCESSFULLY!");

  // Finalize the update
  if (!Update.end()) {
    Update.printError(Serial);
    handleErrorState("UPDATE_FINALIZE_FAILED");
    return;
  }

  Serial.println("UPDATE SUCCESSFUL! Rebooting into new firmware...");
  ESP.restart();
}

// ====================================================================================
// HELPER FUNCTIONS (No changes needed below this line)
// ====================================================================================

int compareVersionStrings(const String& leftVersion, const String& rightVersion) {
  int leftIdx = 0;
  int rightIdx = 0;
  while (true) {
    long leftPart = 0;
    long rightPart = 0;
    while (leftIdx < (int)leftVersion.length() && isDigit(leftVersion[leftIdx])) {
      leftPart = leftPart * 10 + (leftVersion[leftIdx] - '0');
      leftIdx++;
    }
    if (leftIdx < (int)leftVersion.length() && leftVersion[leftIdx] == '.') leftIdx++;
    while (rightIdx < (int)rightVersion.length() && isDigit(rightVersion[rightIdx])) {
      rightPart = rightPart * 10 + (rightVersion[rightIdx] - '0');
      rightIdx++;
    }
    if (rightIdx < (int)rightVersion.length() && rightVersion[rightIdx] == '.') rightIdx++;
    if (leftPart > rightPart) return 1;
    if (leftPart < rightPart) return -1;
    bool leftDone = leftIdx >= (int)leftVersion.length();
    bool rightDone = rightIdx >= (int)rightVersion.length();
    if (leftDone && rightDone) return 0;
  }
}

bool verify_signature(uint8_t* sha256_hash, uint8_t* signature, size_t sig_len) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)PUBLIC_KEY, strlen(PUBLIC_KEY) + 1);
  if (ret != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }
  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, sha256_hash, 32, signature, sig_len);
  mbedtls_pk_free(&pk);
  return ret == 0;
}

void handleErrorState(String errorCode) {
  Serial.println("An error occurred. Error Code: " + errorCode);
  Serial.println("Device will not attempt another update until rebooted.");
}

bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }
  WiFi.disconnect(true);
  delay(100);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    Serial.print(".");
    delay(500);
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("WiFi Connected! IP: " + WiFi.localIP().toString());
    return true;
  } else {
    Serial.println("WiFi connection failed.");
    return false;
  }
}

bool validateConfiguration() {
  bool valid = true;
  if (strlen(WIFI_SSID) == 0) { Serial.println("ERROR: WIFI_SSID is empty"); valid = false; }
  if (strlen(GITHUB_OWNER) == 0) { Serial.println("ERROR: GITHUB_OWNER is empty"); valid = false; }
  if (strlen(FIRMWARE_VERSION) == 0) { Serial.println("ERROR: FIRMWARE_VERSION is empty"); valid = false; }
  if (strlen(PUBLIC_KEY) < 100) { Serial.println("ERROR: PUBLIC_KEY is missing or too short"); valid = false; }
  return valid;
}