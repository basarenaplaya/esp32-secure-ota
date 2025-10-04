#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

void checkForUpdates();
void performSecureUpdate(String firmwareUrl, String signatureUrl);
bool verify_signature(uint8_t* sha256_hash, uint8_t* signature, size_t sig_len);
void handleErrorState(String errorCode);
bool connectWiFi(); 
int compareVersionStrings(const String& leftVersion, const String& rightVersion);

const char* WIFI_SSID = "Ooredoo-X16-18CFD5";
const char* WIFI_PASSWORD = "B30C0259Er-04";

const char* SERVER_URL = "http://192.168.0.15:3000"; 

const char* FIRMWARE_VERSION = "1.2";


const long UPDATE_CHECK_INTERVAL = 300000; 
unsigned long previousMillisUpdate = 0;
const long VERSION_PRINT_INTERVAL = 3000;
unsigned long previousMillisPrint = 0;


const char* PUBLIC_KEY = R"KEY(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnhaptxzW3VmQRf6EHd2
VyfIaHo5i/D3l/D3SHqY3bejL99lmDCZdGhiDe/LzvhmNACHgYac25Nb/Mhhkwpf
xsl1/KI9o+lsbpQLeBjdCOC130Jw86P+fCeC4LWJrCsQsqpPO5JE4GqGD1aF5EXj
5l+otPJp5aZ+7WVUeLvyocx9lEZjz30kU0pH2G2YqC42hovu5Fng8GeD/lGc39j2
skA1cWvNsl4XSywl/cLSLqtQIFkG7KbXvvqgAnsL7R8n4VWBmUdWJoPZDng97/Kf
HDBTdx+FPKZ4fU2pVysBcnOEmTAnIRHvr87QX6XYqYnhlaWNTVM4plIB73cQTPME
zQIDAQAB
-----END PUBLIC KEY-----
)KEY";


void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);
  Serial.println("\n\nBooting Secure OTA Client (Simplified WiFi)...");
  Serial.println("Current Firmware Version: " + String(FIRMWARE_VERSION));

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
  
  // LED blinking functionality
  static unsigned long previousLedMillis = 0;
  static bool ledState = false;
  
  if (currentMillis - previousLedMillis >= 1000) {  // 1 second interval
    previousLedMillis = currentMillis;
    ledState = !ledState;
    if (ledState) {
      digitalWrite(2, HIGH);
    } else {
      digitalWrite(2, LOW);
    }
  }

}



void checkForUpdates() {
  String manifestUrl = String(SERVER_URL) + "/api/manifest.json";
  Serial.println("Fetching manifest from: " + manifestUrl);
  
  HTTPClient http;
  http.begin(manifestUrl);
  int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.println("PROBLEM: Failed to download manifest. HTTP Code: " + String(httpCode));
    http.end();
    handleErrorState("MANIFEST_DOWNLOAD_FAILED");
    return;
  }
  
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, http.getStream());
  if (error) {
    Serial.println("PROBLEM: Failed to parse JSON manifest.");
    http.end();
    handleErrorState("MANIFEST_PARSE_FAILED");
    return;
  }

  String newVersion = String(doc["version"].as<const char*>() ? doc["version"].as<const char*>() : "");
  if (newVersion.length() == 0 && doc["version"].is<float>()) {
    double verNum = doc["version"].as<double>();
    char buf[32];
    dtostrf(verNum, 0, 3, buf); // keep up to 3 decimal places if provided
    String s(buf);
    s.trim();
    while (s.endsWith("0")) s.remove(s.length()-1);
    if (s.endsWith(".")) s.remove(s.length()-1);
    newVersion = s;
  }
  String firmwareUrl = String(SERVER_URL) + doc["file_url"].as<const char*>();
  String signatureUrl = String(SERVER_URL) + doc["signature_url"].as<const char*>();

  http.end();

  Serial.println("Update Check: Current version is " + String(FIRMWARE_VERSION) + ", Server version is " + newVersion);

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