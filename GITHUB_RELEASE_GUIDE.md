# GitHub Release Setup Guide

## How to Create a GitHub Release for OTA Updates

### 1. Prepare Your Release Files

When creating a new release, you need to attach these files:

- **`firmware.bin`** - The compiled firmware binary
- **`signature.bin`** - The digital signature of the firmware

### 2. Creating the Release

1. Go to your GitHub repository
2. Click on "Releases" → "Create a new release"
3. Set the **Tag version** (e.g., `v1.3`, `v2.0`) - this will be compared with `FIRMWARE_VERSION`
4. Set the **Release title** (e.g., "Firmware v1.3")
5. Add release notes describing the changes
6. **Attach files**:
   - Upload `firmware.bin`
   - Upload `signature.bin`
7. Click "Publish release"

### 3. File Naming Requirements

The firmware expects these exact filenames in the release assets:
- `firmware.bin` - The firmware binary
- `signature.bin` - The signature file

### 4. Version Comparison

The firmware compares the GitHub release tag (e.g., `v1.3`) with the `FIRMWARE_VERSION` in your config.

**Example:**
- Current firmware version: `1.2` (in config.h)
- GitHub release tag: `v1.3`
- Result: Update will be triggered

### 5. Security

- The `signature.bin` file should be created using your private key
- The firmware verifies the signature using the public key in `config.h`
- Only signed firmware will be accepted

### 6. Testing

1. Create a test release with version higher than current
2. Upload test `firmware.bin` and `signature.bin` files
3. The ESP32 should detect the new version and attempt to update

## Example Release Structure

```
Release: v1.3
├── firmware.bin (your compiled firmware)
└── signature.bin (digital signature)
```

## Configuration

Make sure your `secrets/config.h` has the correct GitHub repository:

```cpp
const char* GITHUB_OWNER = "your-username";
const char* GITHUB_REPO = "your-repo-name";
const char* GITHUB_RELEASES_URL = "https://api.github.com/repos/your-username/your-repo-name/releases/latest";
```
