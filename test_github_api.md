# GitHub API Test Guide

## Testing Your GitHub Repository

### 1. Check if Repository Exists
Visit: `https://api.github.com/repos/basarenaplaya/esp32-secure-ota`

### 2. Check if Releases Exist
Visit: `https://api.github.com/repos/basarenaplaya/esp32-secure-ota/releases`

### 3. Check Latest Release
Visit: `https://api.github.com/repos/basarenaplaya/esp32-secure-ota/releases/latest`

## Common Issues

### Rate Limiting (403 Forbidden)
- GitHub limits unauthenticated requests to 60/hour per IP
- Solution: Add authentication or wait

### Repository Not Found (404)
- Check if repository name is correct
- Check if repository is public
- Check if repository exists

### No Releases (Empty Response)
- Repository exists but has no releases
- Create a release with `firmware.bin` and `signature.bin`

## Testing Steps

1. **Verify Repository**: Visit the repository URL in browser
2. **Check Releases**: Look for existing releases
3. **Create Test Release**: If none exist, create one with:
   - Tag: `v1.1` (higher than current `1.0`)
   - Attach `firmware.bin`
   - Attach `signature.bin`

## Expected JSON Response Structure

```json
{
  "tag_name": "v1.1",
  "assets": [
    {
      "name": "firmware.bin",
      "browser_download_url": "https://github.com/.../firmware.bin"
    },
    {
      "name": "signature.bin", 
      "browser_download_url": "https://github.com/.../signature.bin"
    }
  ]
}
```
