# Web Crypto API Test Miniapp

## Overview

This is a standalone miniapp project designed to comprehensively test Web Crypto API functionality, specifically focusing on identifying what works and what fails on iOS release builds. The miniapp demonstrates the full encryption/decryption flow using JWE (JSON Web Encryption) format.

## Problem Description

The super app team has identified that Web Crypto API operations (specifically `crypto.subtle` for AES-GCM encryption/decryption) fail on iOS release builds, while they work correctly on:
- Android release builds
- iOS debug builds

This test miniapp helps identify exactly which Web Crypto API calls fail and provides detailed diagnostics to assist in debugging the root cause.

## Project Structure

```
crypto-test-miniapp/
├── app.json                 # Miniapp configuration (single test page)
├── app.js                   # Minimal app initialization
├── app.acss                 # Basic styling
├── pages/
│   └── test/
│       ├── test.json        # Page configuration
│       ├── test.js          # Comprehensive test page logic
│       ├── test.axml        # Test page UI with detailed results
│       └── test.acss        # Test page styles
├── shared/
│   ├── libs/
│   │   └── crypto-js.js     # crypto-js library (for PBKDF2 and HMAC)
│   └── services/
│       └── CryptoTestService.js  # Comprehensive crypto test service
└── README.md                # This file
```

## How to Run

1. **Open the project** in your miniapp development environment (Alipay miniapp IDE or similar)

2. **Build and run** the miniapp on:
   - Android device (debug build)
   - Android device (release build)
   - iOS device (debug build)
   - iOS device (release build) - **This is where failures are expected**

3. **Navigate to the test page** - The app automatically loads the test page on launch

4. **Review test results** - All tests run automatically on page load. Results are displayed in organized sections with detailed error information.

5. **Re-run tests** - Use the "Re-run All Tests" button to execute all tests again

## Test Categories

### 1. Environment Information
- **Platform Detection**: Identifies iOS vs Android
- **Build Type Detection**: Attempts to infer debug vs release build
- **Available APIs**: Lists which crypto APIs are available:
  - `crypto` object
  - `crypto.subtle` object
  - `crypto.getRandomValues()` function
  - `crypto-js` library
  - `TextEncoder` / `TextDecoder`
  - `btoa` / `atob`

### 2. Basic API Tests
- **Web Crypto API Availability**: Checks if `crypto` and `crypto.subtle` exist
- **crypto.getRandomValues()**: Tests random byte generation

### 3. crypto-js Tests (Expected to Work Everywhere)
These tests use the `crypto-js` library, which should work on all platforms:
- **PBKDF2 Key Derivation**: Tests key derivation using PBKDF2 with SHA-256 (10,000 iterations)
- **HMAC-SHA256 Signing**: Tests HMAC signature generation

### 4. Web Crypto API Tests (Expected to Fail on iOS Release)
These tests use the Web Crypto API, which fails on iOS release builds:
- **AES-GCM Key Import**: Tests `crypto.subtle.importKey()` for AES-GCM
- **AES-GCM Encryption**: Tests `crypto.subtle.encrypt()` with AES-GCM
- **AES-GCM Decryption**: Tests `crypto.subtle.decrypt()` with AES-GCM

### 5. Full Flow Tests
These tests combine multiple operations to test the complete JWE flow:
- **Full JWE Encryption**: Complete encryption flow (PBKDF2 + AES-GCM + Base64)
- **Full JWE Decryption**: Complete decryption flow (Base64 + AES-GCM + PBKDF2)
- **Complete Encrypt-Decrypt Cycle**: Round-trip test to verify data integrity

## Expected Behavior

### Android Release Build
- ✅ All tests should pass
- ✅ Web Crypto API operations work correctly
- ✅ crypto-js operations work correctly

### iOS Debug Build
- ✅ All tests should pass
- ✅ Web Crypto API operations work correctly
- ✅ crypto-js operations work correctly

### iOS Release Build
- ✅ Basic API tests: Should pass (availability checks)
- ✅ crypto-js tests: Should pass (PBKDF2, HMAC)
- ❌ Web Crypto API tests: **Expected to fail**
  - `crypto.subtle.importKey()` may fail
  - `crypto.subtle.encrypt()` may fail
  - `crypto.subtle.decrypt()` may fail
- ❌ Full flow tests: **Expected to fail** (due to AES-GCM failures)

## Technical Details

### Web Crypto API Usage

The miniapp uses the Web Crypto API for AES-GCM encryption/decryption:

```javascript
// Key import
const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,        // 32 bytes (256 bits) for AES-256
    'AES-GCM',
    false,
    ['encrypt', 'decrypt']
);

// Encryption
const encrypted = await crypto.subtle.encrypt(
    {
        name: 'AES-GCM',
        iv: ivBytes  // 12 bytes for GCM
    },
    cryptoKey,
    plaintextBytes
);

// Decryption
const decrypted = await crypto.subtle.decrypt(
    {
        name: 'AES-GCM',
        iv: ivBytes
    },
    cryptoKey,
    encryptedBytes
);
```

### crypto-js Usage

The miniapp uses `crypto-js` for operations that should work everywhere:

```javascript
// PBKDF2 key derivation
const key = CryptoJS.PBKDF2(userId, salt, {
    keySize: 8,        // 8 words = 32 bytes = 256 bits
    iterations: 10000,
    hasher: CryptoJS.algo.SHA256
});

// HMAC-SHA256 signing
const hmac = CryptoJS.HmacSHA256(data, key);
```

### JWE Format

The miniapp uses JWE (JSON Web Encryption) format:
- **Header**: Base64URL-encoded JSON with algorithm info
- **IV**: 12-byte initialization vector (Base64URL-encoded)
- **Ciphertext**: Encrypted payload (Base64URL-encoded)
- **Tag**: 16-byte authentication tag (Base64URL-encoded)

Format: `header.iv.ciphertext.tag`

## Test Data

The miniapp uses non-sensitive test data:
- **User ID**: `"test-user-123"`
- **Salt**: `"test-salt-2024"`
- **Payload**: `{"message": "Hello World", "timestamp": 1234567890, "data": {"key": "value"}}`
- **PBKDF2 Iterations**: 10,000 (same as production)

## Code Structure

### CryptoTestService.js

The main test service (`shared/services/CryptoTestService.js`) contains:
- **Test Methods**: Each test method returns a detailed result object with:
  - Test name and description
  - Expected result
  - Actual result
  - Pass/fail status
  - Error details (if failed)
  - Execution time
- **Utility Methods**: Extracted from `EncryptionService.js`:
  - `deriveKeyFromUserId()` - PBKDF2 key derivation
  - `aesGcmEncrypt()` - AES-GCM encryption
  - `aesGcmDecrypt()` - AES-GCM decryption
  - `createJWE()` - JWE token creation
  - `decryptJWE()` - JWE token decryption
  - Base64 encoding/decoding utilities
  - String/bytes conversion utilities
  - Random byte generation

### Test Page (pages/test/)

- **test.js**: Runs all tests automatically on page load, organizes results by category
- **test.axml**: Displays test results in organized sections with color coding
- **test.acss**: Styles with green for pass, red for fail

## What to Look For When Debugging

### On iOS Release Builds

1. **Check which specific API calls fail**:
   - Does `crypto.subtle` exist but throw errors?
   - Does `crypto.subtle.importKey()` fail?
   - Does `crypto.subtle.encrypt()` fail?
   - Does `crypto.subtle.decrypt()` fail?

2. **Error Details**:
   - Error message
   - Error type/name
   - Stack trace (if available)
   - Which specific operation failed

3. **Environment Info**:
   - Platform detection
   - Build type inference
   - Available APIs checklist

4. **Compare with Working Platforms**:
   - Android release: All tests pass
   - iOS debug: All tests pass
   - iOS release: Web Crypto API tests fail

### Common Issues

- **`crypto.subtle` is undefined**: Web Crypto API not available
- **`crypto.subtle.importKey()` throws error**: Key import fails (likely iOS release issue)
- **`crypto.subtle.encrypt()` throws error**: Encryption fails (likely iOS release issue)
- **`crypto.subtle.decrypt()` throws error**: Decryption fails (likely iOS release issue)

## Error Handling

All errors are caught and displayed with full details:
- Error message
- Error type/name
- Stack trace (if available)
- Context (which test was running)

Errors are logged to the console AND displayed on the page for easy debugging.

## Success Criteria

The miniapp successfully:
- ✅ Runs on Android release builds (all tests pass)
- ✅ Runs on iOS debug builds (all tests pass)
- ✅ Clearly shows which tests fail on iOS release builds
- ✅ Demonstrates exact Web Crypto API calls that fail
- ✅ Shows crypto-js-based operations (PBKDF2, HMAC) work correctly
- ✅ Shows Web Crypto API operations (AES-GCM) fail on iOS release
- ✅ Provides comprehensive diagnostics for debugging
- ✅ Contains no sensitive information or business logic

## Contact

For questions or issues related to this test miniapp, contact the super app team.

## Notes

- This miniapp is for testing purposes only
- No sensitive data is used in tests
- All test data is non-production values
- The miniapp is standalone with no external dependencies (except crypto-js library)

