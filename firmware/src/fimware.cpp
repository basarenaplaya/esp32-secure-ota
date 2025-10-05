#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "../../secrets/config.h"

void checkForUpdates();
void performSecureUpdate(String firmwareUrl, String signatureUrl);
bool verify_signature(uint8_t* sha256_hash, uint8_t* signature, size_t sig_len);
void handleErrorState(String errorCode);
bool connectWiFi(); 
int compareVersionStrings(const String& leftVersion, const String& rightVersion);
bool validateConfiguration();



// Configuration values are now loaded from config.h
unsigned long previousMillisUpdate = 0;
unsigned long previousMillisPrint = 0;


void setup() {
  Serial.begin(SERIAL_BAUD_RATE);
  Serial.println("\n\nBooting Secure OTA Client (Simplified WiFi)...");
  Serial.println("Current Firmware Version: " + String(FIRMWARE_VERSION));

  // Validate configuration
  if (!validateConfiguration()) {
    Serial.println("ERROR: Configuration validation failed!");
    handleErrorState("CONFIG_VALIDATION_FAILED");
    return;
  }

  if (!connectWiFi()) {
    Serial.println("Initial WiFi connection failed. Will retry periodically in the main loop.");
  }
  
  if (WiFi.status() == WL_CONNECTED) {
      checkForUpdates();
  }
}


void loop() {
  unsigned long currentMillis = millis();

  if (currentMillis - previousMillisUpdate >= UPDATE_CHECK_INTERVAL) {
    previousMillisUpdate = currentMillis;
    Serial.println("--------------------");
    Serial.println("Checking for a new firmware version...");
    
    // Attempt to connect WiFi if not already connected
    if (WiFi.status() != WL_CONNECTED) {
      connectWiFi();
    }
    
    // Only check for updates if WiFi is successfully connected
    if (WiFi.status() == WL_CONNECTED) {
      checkForUpdates();
    } else {
      Serial.println("WiFi is not connected.");
    }
  }

  // --- Timer 2: Print the current version number periodically ---
  if (currentMillis - previousMillisPrint >= VERSION_PRINT_INTERVAL) {
    previousMillisPrint = currentMillis;
    Serial.println("Status: Alive. Running firmware version: " + String(FIRMWARE_VERSION));
  }
}

void checkForUpdates() {
  Serial.println("Fetching latest release from GitHub: " + String(GITHUB_RELEASES_URL));
  Serial.println("Repository: " + String(GITHUB_OWNER) + "/" + String(GITHUB_REPO));
  Serial.println("Free heap: " + String(ESP.getFreeHeap()) + " bytes");
  
  HTTPClient http;
  http.begin(GITHUB_RELEASES_URL);
  http.addHeader("User-Agent", "ESP32-OTA-Client/1.0");
  http.addHeader("Accept", "application/vnd.github.v3+json");
  
  int httpCode = http.GET();
  Serial.println("HTTP Response Code: " + String(httpCode));
  
  if (httpCode != HTTP_CODE_OK) {
    Serial.println("PROBLEM: Failed to fetch GitHub release. HTTP Code: " + String(httpCode));
    if (httpCode == 403) {
      Serial.println("This might be due to GitHub rate limiting. Try again later.");
    } else if (httpCode == 404) {
      Serial.println("Repository or release not found. Check your GitHub configuration.");
    }
    http.end();
    handleErrorState("GITHUB_RELEASE_FETCH_FAILED");
    return;
  }
  
  Serial.println("GitHub API response received successfully");
  
  // Parse JSON manually to avoid large buffer issues
  String response = http.getString();
  http.end();
  
  Serial.println("Response length: " + String(response.length()) + " bytes");
  Serial.println("Free heap before parsing: " + String(ESP.getFreeHeap()) + " bytes");
  
  // Manual JSON parsing to avoid stack overflow
  String newVersion = "";
  String firmwareUrl = "";
  String signatureUrl = "";
  
  // Extract tag_name
  int tagStart = response.indexOf("\"tag_name\":\"");
  if (tagStart != -1) {
    tagStart += 12; // Skip "tag_name":"
    int tagEnd = response.indexOf("\"", tagStart);
    if (tagEnd != -1) {
      newVersion = response.substring(tagStart, tagEnd);
    }
  }
  
  if (newVersion.length() == 0) {
    Serial.println("PROBLEM: No tag_name found in GitHub release.");
    Serial.println("First 200 chars: " + response.substring(0, 200));
    handleErrorState("GITHUB_RELEASE_NO_VERSION");
    return;
  }
  
  Serial.println("Found version: " + newVersion);
  Serial.println("Free heap after version extraction: " + String(ESP.getFreeHeap()) + " bytes");
  
  // Extract assets URLs - improved parsing
  int assetsStart = response.indexOf("\"assets\":[");
  if (assetsStart != -1) {
    int assetsEnd = response.indexOf("]", assetsStart);
    if (assetsEnd != -1) {
      String assetsSection = response.substring(assetsStart, assetsEnd);
      Serial.println("Assets section found, length: " + String(assetsSection.length()));
      
      // Look for firmware.bin
      int firmwareStart = assetsSection.indexOf("\"name\":\"firmware.bin\"");
      if (firmwareStart != -1) {
        Serial.println("Found firmware.bin in assets");
        int urlStart = assetsSection.indexOf("\"browser_download_url\":\"", firmwareStart);
        if (urlStart != -1) {
          urlStart += 22; // Skip "browser_download_url":"
          int urlEnd = assetsSection.indexOf("\"", urlStart);
          if (urlEnd != -1) {
            firmwareUrl = assetsSection.substring(urlStart, urlEnd);
            Serial.println("Extracted firmware URL: " + firmwareUrl);
          }
        }
      } else {
        Serial.println("firmware.bin not found in assets");
      }
      
      // Look for signature.bin
      int signatureStart = assetsSection.indexOf("\"name\":\"signature.bin\"");
      if (signatureStart != -1) {
        Serial.println("Found signature.bin in assets");
        int urlStart = assetsSection.indexOf("\"browser_download_url\":\"", signatureStart);
        if (urlStart != -1) {
          urlStart += 22; // Skip "browser_download_url":"
          int urlEnd = assetsSection.indexOf("\"", urlStart);
          if (urlEnd != -1) {
            signatureUrl = assetsSection.substring(urlStart, urlEnd);
            Serial.println("Extracted signature URL: " + signatureUrl);
          }
        }
      } else {
        Serial.println("signature.bin not found in assets");
      }
      
      // Show what assets are actually available
      Serial.println("Available assets in release:");
      int nameStart = assetsSection.indexOf("\"name\":\"");
      while (nameStart != -1) {
        nameStart += 8; // Skip "name":"
        int nameEnd = assetsSection.indexOf("\"", nameStart);
        if (nameEnd != -1) {
          String assetName = assetsSection.substring(nameStart, nameEnd);
          Serial.println("- " + assetName);
          nameStart = assetsSection.indexOf("\"name\":\"", nameEnd);
        } else {
          break;
        }
      }
    } else {
      Serial.println("Assets section end not found");
    }
  } else {
    Serial.println("Assets section not found");
  }

  Serial.println("Firmware URL: " + firmwareUrl);
  Serial.println("Signature URL: " + signatureUrl);
  Serial.println("Free heap after URL extraction: " + String(ESP.getFreeHeap()) + " bytes");
  
  if (firmwareUrl.length() == 0 || signatureUrl.length() == 0) {
    Serial.println("PROBLEM: Required files (firmware.bin or signature.bin) not found in release assets.");
    Serial.println("Make sure your GitHub release has both firmware.bin and signature.bin files attached.");
    handleErrorState("GITHUB_RELEASE_MISSING_FILES");
    return;
  }

  Serial.println("Update Check: Current version is " + String(FIRMWARE_VERSION) + ", GitHub release version is " + newVersion);

  int cmp = compareVersionStrings(newVersion, String(FIRMWARE_VERSION));
  if (cmp > 0) {
    Serial.println("Action: New version found. Starting secure update process.");
    performSecureUpdate(firmwareUrl, signatureUrl);
  } else {
    Serial.println("Action: No new version available.");
  }
}

void performSecureUpdate(String firmwareUrl, String signatureUrl) {
  HTTPClient http;
  
  http.begin(firmwareUrl);
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
    Serial.println("PROBLEM: Not enough space to begin OTA update.");
    Update.printError(Serial);
    http.end();
    handleErrorState("INSUFFICIENT_SPACE");
    return;
  }
  
  Serial.println("Downloading new firmware...");
  WiFiClient& stream = http.getStream();
  const size_t bufferSize = 1024;
  uint8_t buffer[bufferSize];
  size_t totalWritten = 0;

  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts_ret(&shaCtx, 0);

  while (totalWritten < (size_t)contentLength) {
    size_t toRead = bufferSize;
    size_t readLen = stream.readBytes(buffer, toRead);
    if (readLen == 0) {
      break;
    }
    size_t wrote = Update.write(buffer, readLen);
    if (wrote != readLen) {
      Serial.println("PROBLEM: Firmware write chunk failed.");
      Update.abort();
      http.end();
      handleErrorState("FIRMWARE_WRITE_INCOMPLETE");
      return;
    }
    mbedtls_sha256_update_ret(&shaCtx, buffer, readLen);
    totalWritten += readLen;
  }

  if (totalWritten != (size_t)contentLength) {
    Serial.println("PROBLEM: Firmware size mismatch while downloading.");
    Update.abort();
    http.end();
    handleErrorState("FIRMWARE_WRITE_INCOMPLETE");
    return;
  }

  uint8_t shaResult[32];
  mbedtls_sha256_finish_ret(&shaCtx, shaResult);
  mbedtls_sha256_free(&shaCtx);
  http.end();

  http.begin(signatureUrl);
  httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.println("PROBLEM: Failed to download signature file.");
    Update.abort();
    http.end();
    handleErrorState("SIGNATURE_DOWNLOAD_FAILED");
    return;
  }
  
  uint8_t signature[256];
  int sigLen = http.getStream().readBytes(signature, 256);
  http.end();
  
  Serial.println("Verifying signature...");
  if (!verify_signature(shaResult, signature, sigLen)) {
    Serial.println("PROBLEM: SIGNATURE VERIFICATION FAILED! This is a major security alert.");
    Update.abort();
    handleErrorState("SIGNATURE_VERIFICATION_FAILED");
    return;
  }
  Serial.println("SIGNATURE VERIFIED SUCCESSFULLY!");

  if (!Update.end()) {
    Serial.println("PROBLEM: An error occurred finalizing the update after verification.");
    Update.printError(Serial);
    handleErrorState("UPDATE_FINALIZE_FAILED");
    return;
  }

  Serial.println("UPDATE SUCCESSFUL! Rebooting into new firmware...");
  ESP.restart();
}


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
    if (leftIdx < (int)leftVersion.length() && leftVersion[leftIdx] == '.') {
      leftIdx++;
    }

    while (rightIdx < (int)rightVersion.length() && isDigit(rightVersion[rightIdx])) {
      rightPart = rightPart * 10 + (rightVersion[rightIdx] - '0');
      rightIdx++;
    }
    if (rightIdx < (int)rightVersion.length() && rightVersion[rightIdx] == '.') {
      rightIdx++;
    }

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
    Serial.println("Internal Problem: Failed to parse public key: " + String(ret));
    mbedtls_pk_free(&pk);
    return false;
  }

  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, sha256_hash, 32, signature, sig_len);
  mbedtls_pk_free(&pk);
  
  if (ret == 0) return true;
  
  Serial.println("Internal Problem: Failed to verify signature, mbedtls code: " + String(ret));
  return false;
}

void handleErrorState(String errorCode) {
  Serial.println("An unrecoverable error occurred. Error Code: " + errorCode);
  Serial.println("The device will not attempt another update until it is rebooted.");
  Serial.println("Free heap: " + String(ESP.getFreeHeap()) + " bytes");
  delay(5000); // Wait 5 seconds before continuing
}


bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }
  
  WiFi.mode(WIFI_STA); // Optional
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.println("\nConnecting");

  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(100);
  }

  Serial.println("\nConnected to the WiFi network");
  Serial.print("Local ESP32 IP: ");
  Serial.println(WiFi.localIP());
  return true;
}

bool validateConfiguration() {
  Serial.println("Validating configuration...");
  
  // Check WiFi credentials
  if (strlen(WIFI_SSID) == 0) {
    Serial.println("ERROR: WIFI_SSID is empty");
    return false;
  }
  
  if (strlen(WIFI_PASSWORD) == 0) {
    Serial.println("ERROR: WIFI_PASSWORD is empty");
    return false;
  }
  
  // Check GitHub configuration
  if (strlen(GITHUB_OWNER) == 0) {
    Serial.println("ERROR: GITHUB_OWNER is empty");
    return false;
  }
  
  if (strlen(GITHUB_REPO) == 0) {
    Serial.println("ERROR: GITHUB_REPO is empty");
    return false;
  }
  
  if (strlen(GITHUB_RELEASES_URL) == 0) {
    Serial.println("ERROR: GITHUB_RELEASES_URL is empty");
    return false;
  }
  
  // Check firmware version
  if (strlen(FIRMWARE_VERSION) == 0) {
    Serial.println("ERROR: FIRMWARE_VERSION is empty");
    return false;
  }
  
  // Check intervals are positive
  if (UPDATE_CHECK_INTERVAL <= 0) {
    Serial.println("ERROR: UPDATE_CHECK_INTERVAL must be positive");
    return false;
  }
  
  if (VERSION_PRINT_INTERVAL <= 0) {
    Serial.println("ERROR: VERSION_PRINT_INTERVAL must be positive");
    return false;
  }
  
  
  // Check serial baud rate
  if (SERIAL_BAUD_RATE <= 0) {
    Serial.println("ERROR: SERIAL_BAUD_RATE must be positive");
    return false;
  }
  
  // Check public key
  if (strlen(PUBLIC_KEY) == 0) {
    Serial.println("ERROR: PUBLIC_KEY is empty");
    return false;
  }
  
  Serial.println("Configuration validation passed!");
  return true;
}