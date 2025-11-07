/**
 * Crypto Test Service - Comprehensive Web Crypto API Testing
 * 
 * Purpose: Test all crypto operations to identify what works and what fails on iOS release builds
 * 
 * Test Categories:
 * 1. Environment detection (platform, build type, available APIs)
 * 2. Basic API tests (crypto object, crypto.subtle, getRandomValues)
 * 3. crypto-js tests (PBKDF2, HMAC - should work everywhere)
 * 4. Web Crypto API tests (AES-GCM - expected to fail on iOS release)
 * 5. Full flow tests (complete JWE encrypt/decrypt cycle)
 */

// Import crypto-js from local file
let CryptoJS = null;
try {
    CryptoJS = require('../libs/crypto-js');
    if (CryptoJS && CryptoJS.PBKDF2) {
        console.log('[CryptoTestService] crypto-js loaded successfully');
    } else {
        console.warn('[CryptoTestService] crypto-js loaded but missing required APIs');
        CryptoJS = null;
    }
} catch (e) {
    console.error('[CryptoTestService] Failed to load crypto-js:', e);
}

class CryptoTestService {
    constructor(config = {}) {
        this.salt = config.salt || 'test-salt-2024';
        this.iterations = config.iterations || 10000;
        this.testUserId = 'test-user-123';
        this.testPayload = {
            message: 'Hello World',
            timestamp: 1234567890,
            data: { key: 'value' }
        };
    }

    /**
     * Get environment information (platform, build type, available APIs)
     * @returns {Promise<Object>} Environment info
     */
    async getEnvironmentInfo() {
        const info = {
            platform: 'Unknown',
            buildType: 'Unknown',
            availableAPIs: {
                crypto: typeof crypto !== 'undefined',
                cryptoSubtle: typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined',
                cryptoGetRandomValues: typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function',
                cryptoJS: CryptoJS !== null,
                textEncoder: typeof TextEncoder !== 'undefined',
                textDecoder: typeof TextDecoder !== 'undefined',
                btoa: typeof btoa !== 'undefined',
                atob: typeof atob !== 'undefined'
            },
            cryptoObjectDetails: {},
            systemInfo: null
        };

        // Try to get system info using miniapp API
        try {
            if (typeof my !== 'undefined' && my.getSystemInfo) {
                const systemInfo = await new Promise((resolve, reject) => {
                    my.getSystemInfo({
                        success: (res) => resolve(res),
                        fail: (err) => reject(err)
                    });
                });
                info.systemInfo = systemInfo;
                info.platform = systemInfo.platform || 'Unknown';
                
                // Try to infer build type from system info or error behavior
                // Debug builds often have more verbose logging or different behavior
                if (systemInfo.platform === 'iOS') {
                    // We'll test crypto.subtle to infer build type
                    // If it fails immediately, likely release build
                    try {
                        if (typeof crypto !== 'undefined' && crypto.subtle) {
                            // Try a simple operation to see if it works
                            const testKey = new Uint8Array(32);
                            await crypto.subtle.importKey('raw', testKey, 'AES-GCM', false, ['encrypt']);
                            info.buildType = 'Debug (crypto.subtle works)';
                        } else {
                            info.buildType = 'Release (crypto.subtle unavailable)';
                        }
                    } catch (e) {
                        info.buildType = 'Release (crypto.subtle fails: ' + e.message + ')';
                    }
                } else {
                    info.buildType = 'Unknown';
                }
            }
        } catch (e) {
            console.warn('[CryptoTestService] Could not get system info:', e);
        }

        // Get crypto object details
        if (typeof crypto !== 'undefined') {
            info.cryptoObjectDetails = {
                type: typeof crypto,
                hasSubtle: typeof crypto.subtle !== 'undefined',
                hasGetRandomValues: typeof crypto.getRandomValues === 'function',
                subtleType: typeof crypto.subtle !== 'undefined' ? typeof crypto.subtle : 'undefined'
            };
        }

        return info;
    }

    /**
     * Test Web Crypto API availability
     * @returns {Promise<Object>} Test result
     */
    async testWebCryptoAvailability() {
        const startTime = Date.now();
        const result = {
            name: 'Web Crypto API Availability',
            description: 'Check if crypto and crypto.subtle objects exist',
            expected: 'crypto and crypto.subtle should be available',
            passed: false,
            actual: '',
            error: null,
            duration: 0
        };

        try {
            const cryptoExists = typeof crypto !== 'undefined';
            const subtleExists = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

            result.actual = `crypto: ${cryptoExists ? 'available' : 'unavailable'}, crypto.subtle: ${subtleExists ? 'available' : 'unavailable'}`;
            result.passed = cryptoExists && subtleExists;
            result.duration = Date.now() - startTime;

            if (!result.passed) {
                result.error = {
                    message: 'Web Crypto API not fully available',
                    type: 'AvailabilityError'
                };
            }
        } catch (error) {
            result.actual = 'Error checking availability';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test crypto.getRandomValues() functionality
     * @returns {Promise<Object>} Test result
     */
    async testGetRandomValues() {
        const startTime = Date.now();
        const result = {
            name: 'crypto.getRandomValues()',
            description: 'Test crypto.getRandomValues() for generating random bytes',
            expected: 'Should generate random bytes successfully',
            passed: false,
            actual: '',
            error: null,
            duration: 0
        };

        try {
            if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
                throw new Error('crypto.getRandomValues not available');
            }

            const randomBytes = crypto.getRandomValues(new Uint8Array(16));
            
            if (randomBytes.length !== 16) {
                throw new Error('Expected 16 bytes, got ' + randomBytes.length);
            }

            // Check that bytes are not all zeros (very unlikely but possible)
            let allZeros = true;
            for (let i = 0; i < randomBytes.length; i++) {
                if (randomBytes[i] !== 0) {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros) {
                throw new Error('Random bytes are all zeros (unlikely but possible)');
            }

            result.actual = 'Successfully generated ' + randomBytes.length + ' random bytes';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to generate random bytes';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test PBKDF2 key derivation using crypto-js
     * @returns {Promise<Object>} Test result
     */
    async testPBKDF2() {
        const startTime = Date.now();
        const result = {
            name: 'PBKDF2 Key Derivation (crypto-js)',
            description: 'Test PBKDF2 key derivation using crypto-js library',
            expected: 'Should derive key successfully (works on all platforms)',
            passed: false,
            actual: '',
            error: null,
            duration: 0,
            processSteps: []
        };

        try {
            if (!CryptoJS) {
                throw new Error('crypto-js library not available');
            }

            // Log input
            const inputStep = this.formatProcessStep('Input', {
                userId: this.testUserId,
                salt: this.salt,
                iterations: this.iterations
            });
            result.processSteps.push(inputStep);
            console.log('[PBKDF2] Input:', JSON.stringify(inputStep.data, null, 2));

            const key = await this.deriveKeyFromUserId(this.testUserId);
            
            if (!key || key.length === 0) {
                throw new Error('Derived key is empty');
            }

            // Key should be base64 encoded, so check format
            if (typeof key !== 'string') {
                throw new Error('Derived key is not a string');
            }

            // Log output
            const keyBytes = this.base64ToBytes(key);
            const outputStep = this.formatProcessStep('Derived Key', {
                keyBase64: key,
                keyBytes: keyBytes,
                keyLength: keyBytes.length
            });
            result.processSteps.push(outputStep);
            console.log('[PBKDF2] Derived Key:', JSON.stringify(outputStep.data, null, 2));

            result.actual = 'Successfully derived key (length: ' + key.length + ' chars, ' + keyBytes.length + ' bytes)';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to derive key';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test HMAC-SHA256 using crypto-js
     * @returns {Promise<Object>} Test result
     */
    async testHMAC() {
        const startTime = Date.now();
        const result = {
            name: 'HMAC-SHA256 (crypto-js)',
            description: 'Test HMAC-SHA256 signing using crypto-js library',
            expected: 'Should generate HMAC signature successfully (works on all platforms)',
            passed: false,
            actual: '',
            error: null,
            duration: 0,
            processSteps: []
        };

        try {
            if (!CryptoJS) {
                throw new Error('crypto-js library not available');
            }

            const testData = 'test data for HMAC';
            const inputStep = this.formatProcessStep('Input', {
                data: testData,
                userId: this.testUserId
            });
            result.processSteps.push(inputStep);
            console.log('[HMAC] Input:', JSON.stringify(inputStep.data, null, 2));

            const key = await this.deriveKeyFromUserId(this.testUserId);
            const keyBytes = this.base64ToBytes(key);
            
            const keyStep = this.formatProcessStep('Key', {
                keyBase64: key,
                keyBytes: keyBytes
            });
            result.processSteps.push(keyStep);
            console.log('[HMAC] Key:', JSON.stringify(keyStep.data, null, 2));
            
            const signature = await this.hmacSign(testData, keyBytes);
            
            if (!signature || signature.length === 0) {
                throw new Error('HMAC signature is empty');
            }

            if (signature.length !== 32) {
                throw new Error('Expected 32-byte HMAC signature, got ' + signature.length);
            }

            const outputStep = this.formatProcessStep('HMAC Signature', {
                signature: signature,
                signatureLength: signature.length
            });
            result.processSteps.push(outputStep);
            console.log('[HMAC] Signature:', JSON.stringify(outputStep.data, null, 2));

            result.actual = 'Successfully generated HMAC signature (' + signature.length + ' bytes)';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to generate HMAC signature';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test AES-GCM key import using crypto.subtle.importKey()
     * @returns {Promise<Object>} Test result
     */
    async testAESGCMKeyImport() {
        const startTime = Date.now();
        const result = {
            name: 'AES-GCM Key Import (crypto.subtle.importKey)',
            description: 'Test importing AES-GCM key using crypto.subtle.importKey()',
            expected: 'Should import key successfully (fails on iOS release)',
            passed: false,
            actual: '',
            error: null,
            duration: 0
        };

        try {
            if (typeof crypto === 'undefined' || !crypto.subtle) {
                throw new Error('crypto.subtle not available');
            }

            const keyBytes = new Uint8Array(32); // 256-bit key
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                'AES-GCM',
                false,
                ['encrypt', 'decrypt']
            );

            if (!cryptoKey) {
                throw new Error('importKey returned null or undefined');
            }

            result.actual = 'Successfully imported AES-GCM key';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to import key';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test AES-GCM encryption using crypto.subtle.encrypt()
     * @returns {Promise<Object>} Test result
     */
    async testAESGCMEncryption() {
        const startTime = Date.now();
        const result = {
            name: 'AES-GCM Encryption (crypto.subtle.encrypt)',
            description: 'Test AES-GCM encryption using crypto.subtle.encrypt()',
            expected: 'Should encrypt data successfully (fails on iOS release)',
            passed: false,
            actual: '',
            error: null,
            duration: 0
        };

        try {
            const testData = this.stringToBytes('test encryption data');
            const keyBytes = new Uint8Array(32); // 256-bit key
            const iv = this.generateRandomBytes(12); // 12 bytes for GCM

            const encrypted = await this.aesGcmEncrypt(testData, keyBytes, iv);

            if (!encrypted || !encrypted.ciphertext || !encrypted.tag) {
                throw new Error('Encryption result is invalid');
            }

            if (encrypted.tag.length !== 16) {
                throw new Error('Expected 16-byte tag, got ' + encrypted.tag.length);
            }

            result.actual = 'Successfully encrypted data (ciphertext: ' + encrypted.ciphertext.length + ' bytes, tag: ' + encrypted.tag.length + ' bytes)';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to encrypt data';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test AES-GCM decryption using crypto.subtle.decrypt()
     * @returns {Promise<Object>} Test result
     */
    async testAESGCMDecryption() {
        const startTime = Date.now();
        const result = {
            name: 'AES-GCM Decryption (crypto.subtle.decrypt)',
            description: 'Test AES-GCM decryption using crypto.subtle.decrypt()',
            expected: 'Should decrypt data successfully (fails on iOS release)',
            passed: false,
            actual: '',
            error: null,
            duration: 0
        };

        try {
            const testData = this.stringToBytes('test decryption data');
            const keyBytes = new Uint8Array(32); // 256-bit key
            const iv = this.generateRandomBytes(12); // 12 bytes for GCM

            // First encrypt
            const encrypted = await this.aesGcmEncrypt(testData, keyBytes, iv);

            // Then decrypt
            const decrypted = await this.aesGcmDecrypt(encrypted, keyBytes, iv);

            if (!decrypted || decrypted.length === 0) {
                throw new Error('Decryption result is empty');
            }

            // Verify decrypted data matches original
            if (decrypted.length !== testData.length) {
                throw new Error('Decrypted data length mismatch');
            }

            for (let i = 0; i < testData.length; i++) {
                if (decrypted[i] !== testData[i]) {
                    throw new Error('Decrypted data does not match original');
                }
            }

            result.actual = 'Successfully decrypted data (' + decrypted.length + ' bytes)';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to decrypt data';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test full JWE encryption flow
     * @returns {Promise<Object>} Test result
     */
    async testFullJWEEncryption() {
        const startTime = Date.now();
        const result = {
            name: 'Full JWE Encryption Flow',
            description: 'Test complete JWE encryption (PBKDF2 + AES-GCM + Base64)',
            expected: 'Should create JWE token successfully (fails on iOS release due to AES-GCM)',
            passed: false,
            actual: '',
            error: null,
            duration: 0,
            processSteps: []
        };

        try {
            // Step 1: Input data
            const payload = JSON.stringify(this.testPayload);
            const inputStep = this.formatProcessStep('1. Input Data', {
                payload: payload,
                payloadObject: this.testPayload,
                userId: this.testUserId,
                salt: this.salt
            });
            result.processSteps.push(inputStep);
            console.log('[JWE Encryption] Step 1 - Input:', JSON.stringify(inputStep.data, null, 2));

            // Step 2: Key derivation
            const key = await this.deriveKeyFromUserId(this.testUserId);
            const keyBytes = this.base64ToBytes(key);
            const keyStep = this.formatProcessStep('2. Key Derivation', {
                keyBase64: key,
                keyBytes: keyBytes
            });
            result.processSteps.push(keyStep);
            console.log('[JWE Encryption] Step 2 - Key:', JSON.stringify(keyStep.data, null, 2));

            // Step 3: Create JWE (with detailed steps)
            const header = {
                alg: 'dir',
                enc: 'A256GCM',
                kid: this.testUserId,
                iat: Math.floor(Date.now() / 1000),
                typ: 'JWE'
            };
            const headerJson = JSON.stringify(header);
            const headerBase64 = this.base64UrlEncode(headerJson);
            const headerStep = this.formatProcessStep('3. JWE Header', {
                header: header,
                headerJson: headerJson,
                headerBase64: headerBase64
            });
            result.processSteps.push(headerStep);
            console.log('[JWE Encryption] Step 3 - Header:', JSON.stringify(headerStep.data, null, 2));

            // Step 4: Generate IV
            const iv = this.generateRandomBytes(12);
            const ivBase64 = this.base64UrlEncode(iv);
            const ivStep = this.formatProcessStep('4. IV Generation', {
                iv: iv,
                ivBase64: ivBase64
            });
            result.processSteps.push(ivStep);
            console.log('[JWE Encryption] Step 4 - IV:', JSON.stringify(ivStep.data, null, 2));

            // Step 5: Prepare payload
            const payloadBytes = this.stringToBytes(payload);
            const payloadStep = this.formatProcessStep('5. Payload Preparation', {
                payloadBytes: payloadBytes,
                payloadString: payload
            });
            result.processSteps.push(payloadStep);
            console.log('[JWE Encryption] Step 5 - Payload:', JSON.stringify(payloadStep.data, null, 2));

            // Step 6: AES-GCM Encryption
            const encrypted = await this.aesGcmEncrypt(payloadBytes, keyBytes, iv);
            const encryptionStep = this.formatProcessStep('6. AES-GCM Encryption', {
                ciphertext: encrypted.ciphertext,
                tag: encrypted.tag,
                ciphertextBase64: this.base64UrlEncode(encrypted.ciphertext),
                tagBase64: this.base64UrlEncode(encrypted.tag)
            });
            result.processSteps.push(encryptionStep);
            console.log('[JWE Encryption] Step 6 - Encryption:', JSON.stringify(encryptionStep.data, null, 2));

            // Step 7: Assemble JWE token
            const ciphertextBase64 = this.base64UrlEncode(encrypted.ciphertext);
            const tagBase64 = this.base64UrlEncode(encrypted.tag);
            const jweToken = headerBase64 + '.' + ivBase64 + '.' + ciphertextBase64 + '.' + tagBase64;
            const parts = jweToken.split('.');
            const finalStep = this.formatProcessStep('7. JWE Token Assembly', {
                jweToken: jweToken,
                parts: parts,
                header: parts[0],
                iv: parts[1],
                ciphertext: parts[2],
                tag: parts[3]
            });
            result.processSteps.push(finalStep);
            console.log('[JWE Encryption] Step 7 - Final Token:', JSON.stringify(finalStep.data, null, 2));

            if (!jweToken || jweToken.length === 0) {
                throw new Error('JWE token is empty');
            }

            if (parts.length !== 4) {
                throw new Error('Invalid JWE format - expected 4 parts, got ' + parts.length);
            }

            result.actual = 'Successfully created JWE token (length: ' + jweToken.length + ' chars, parts: ' + parts.length + ')';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to create JWE token';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test full JWE decryption flow
     * @returns {Promise<Object>} Test result
     */
    async testFullJWEDecryption() {
        const startTime = Date.now();
        const result = {
            name: 'Full JWE Decryption Flow',
            description: 'Test complete JWE decryption (Base64 + AES-GCM + PBKDF2)',
            expected: 'Should decrypt JWE token successfully (fails on iOS release due to AES-GCM)',
            passed: false,
            actual: '',
            error: null,
            duration: 0,
            processSteps: []
        };

        try {
            // Step 1: Create JWE token first (for testing)
            const payload = JSON.stringify(this.testPayload);
            const key = await this.deriveKeyFromUserId(this.testUserId);
            const jweToken = await this.createJWE(payload, key, this.testUserId);

            const inputStep = this.formatProcessStep('1. JWE Token Input', {
                jweToken: jweToken,
                keyBase64: key,
                originalPayload: payload
            });
            result.processSteps.push(inputStep);
            console.log('[JWE Decryption] Step 1 - Input:', JSON.stringify(inputStep.data, null, 2));

            // Step 2: Parse JWE token
            const parts = jweToken.split('.');
            if (parts.length !== 4) {
                throw new Error('Invalid JWE format - expected 4 parts, got ' + parts.length);
            }

            const [headerB64, ivB64, ciphertextB64, tagB64] = parts;
            const parseStep = this.formatProcessStep('2. JWE Token Parsing', {
                parts: parts,
                headerBase64: headerB64,
                ivBase64: ivB64,
                ciphertextBase64: ciphertextB64,
                tagBase64: tagB64
            });
            result.processSteps.push(parseStep);
            console.log('[JWE Decryption] Step 2 - Parsed:', JSON.stringify(parseStep.data, null, 2));

            // Step 3: Decode header
            const headerBytes = this.base64UrlDecode(headerB64);
            const headerJson = this.bytesToString(headerBytes);
            const header = JSON.parse(headerJson);
            const headerStep = this.formatProcessStep('3. Header Decoding', {
                headerBytes: headerBytes,
                headerJson: headerJson,
                header: header
            });
            result.processSteps.push(headerStep);
            console.log('[JWE Decryption] Step 3 - Header:', JSON.stringify(headerStep.data, null, 2));

            // Step 4: Decode components
            const iv = this.base64UrlDecode(ivB64);
            const ciphertext = this.base64UrlDecode(ciphertextB64);
            const tag = this.base64UrlDecode(tagB64);
            const decodeStep = this.formatProcessStep('4. Component Decoding', {
                iv: iv,
                ciphertext: ciphertext,
                tag: tag
            });
            result.processSteps.push(decodeStep);
            console.log('[JWE Decryption] Step 4 - Decoded:', JSON.stringify(decodeStep.data, null, 2));

            // Step 5: Prepare key
            const keyBytes = this.base64ToBytes(key);
            const keyStep = this.formatProcessStep('5. Key Preparation', {
                keyBase64: key,
                keyBytes: keyBytes
            });
            result.processSteps.push(keyStep);
            console.log('[JWE Decryption] Step 5 - Key:', JSON.stringify(keyStep.data, null, 2));

            // Step 6: AES-GCM Decryption
            const decrypted = await this.aesGcmDecrypt({ ciphertext, tag }, keyBytes, iv);
            const decryptionStep = this.formatProcessStep('6. AES-GCM Decryption', {
                decryptedBytes: decrypted
            });
            result.processSteps.push(decryptionStep);
            console.log('[JWE Decryption] Step 6 - Decrypted:', JSON.stringify(decryptionStep.data, null, 2));

            // Step 7: Convert to string and parse
            const decryptedJson = this.bytesToString(decrypted);
            const decryptedData = JSON.parse(decryptedJson);
            const finalStep = this.formatProcessStep('7. Final Result', {
                decryptedJson: decryptedJson,
                decryptedData: decryptedData,
                originalPayload: this.testPayload,
                match: JSON.stringify(decryptedData) === JSON.stringify(this.testPayload)
            });
            result.processSteps.push(finalStep);
            console.log('[JWE Decryption] Step 7 - Final:', JSON.stringify(finalStep.data, null, 2));

            // Verify decrypted data matches original
            if (JSON.stringify(decryptedData) !== JSON.stringify(this.testPayload)) {
                throw new Error('Decrypted data does not match original payload');
            }

            result.actual = 'Successfully decrypted JWE token and verified data integrity';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to decrypt JWE token';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    /**
     * Test complete encrypt-then-decrypt cycle
     * @returns {Promise<Object>} Test result
     */
    async testFullEncryptDecryptCycle() {
        const startTime = Date.now();
        const result = {
            name: 'Complete Encrypt-Decrypt Cycle',
            description: 'Test encrypt then decrypt with same data to verify round-trip',
            expected: 'Should encrypt and decrypt successfully (fails on iOS release due to AES-GCM)',
            passed: false,
            actual: '',
            error: null,
            duration: 0,
            processSteps: []
        };

        try {
            // Step 1: Initial data
            const payload = JSON.stringify(this.testPayload);
            const inputStep = this.formatProcessStep('1. Initial Data', {
                payload: payload,
                payloadObject: this.testPayload,
                userId: this.testUserId
            });
            result.processSteps.push(inputStep);
            console.log('[Encrypt-Decrypt Cycle] Step 1 - Input:', JSON.stringify(inputStep.data, null, 2));

            // Step 2: Key derivation
            const key = await this.deriveKeyFromUserId(this.testUserId);
            const keyStep = this.formatProcessStep('2. Key Derivation', {
                keyBase64: key
            });
            result.processSteps.push(keyStep);
            console.log('[Encrypt-Decrypt Cycle] Step 2 - Key:', JSON.stringify(keyStep.data, null, 2));

            // Step 3: Encryption
            const jweToken = await this.createJWE(payload, key, this.testUserId);
            const encryptStep = this.formatProcessStep('3. Encryption Result', {
                jweToken: jweToken,
                jweTokenLength: jweToken.length
            });
            result.processSteps.push(encryptStep);
            console.log('[Encrypt-Decrypt Cycle] Step 3 - Encrypted:', JSON.stringify(encryptStep.data, null, 2));

            // Step 4: Decryption
            const decryptedJson = await this.decryptJWE(jweToken, key);
            const decryptStep = this.formatProcessStep('4. Decryption Result', {
                decryptedJson: decryptedJson
            });
            result.processSteps.push(decryptStep);
            console.log('[Encrypt-Decrypt Cycle] Step 4 - Decrypted:', JSON.stringify(decryptStep.data, null, 2));

            // Step 5: Parse and verify
            const decryptedData = JSON.parse(decryptedJson);
            const verifyStep = this.formatProcessStep('5. Verification', {
                decryptedData: decryptedData,
                originalData: this.testPayload,
                match: JSON.stringify(decryptedData) === JSON.stringify(this.testPayload)
            });
            result.processSteps.push(verifyStep);
            console.log('[Encrypt-Decrypt Cycle] Step 5 - Verification:', JSON.stringify(verifyStep.data, null, 2));

            // Verify
            if (JSON.stringify(decryptedData) !== JSON.stringify(this.testPayload)) {
                throw new Error('Round-trip verification failed');
            }

            result.actual = 'Successfully completed encrypt-decrypt cycle with data verification';
            result.passed = true;
            result.duration = Date.now() - startTime;
        } catch (error) {
            result.actual = 'Failed to complete encrypt-decrypt cycle';
            result.error = {
                message: error.message,
                type: error.name || 'UnknownError',
                stack: error.stack
            };
            result.duration = Date.now() - startTime;
        }

        return result;
    }

    // ========== Utility Methods (extracted from EncryptionService) ==========

    /**
     * Derive encryption key from userId using PBKDF2
     * @param {string} userId - User ID
     * @returns {Promise<string>} Base64-encoded derived key
     */
    async deriveKeyFromUserId(userId) {
        if (!CryptoJS) {
            throw new Error('crypto-js library not available');
        }

        const key = CryptoJS.PBKDF2(userId, this.salt, {
            keySize: 8, // 8 words = 32 bytes = 256 bits (for AES-256)
            iterations: this.iterations,
            hasher: CryptoJS.algo.SHA256
        });

        return key.toString(CryptoJS.enc.Base64);
    }

    /**
     * Create JWE token
     * @param {string} payload - Data to encrypt
     * @param {string} key - Base64-encoded encryption key
     * @param {string} userId - User ID for header
     * @returns {Promise<string>} JWE token
     */
    async createJWE(payload, key, userId) {
        const header = {
            alg: 'dir',
            enc: 'A256GCM',
            kid: userId,
            iat: Math.floor(Date.now() / 1000),
            typ: 'JWE'
        };

        const headerJson = JSON.stringify(header);
        const headerBase64 = this.base64UrlEncode(headerJson);

        const iv = this.generateRandomBytes(12);
        const ivBase64 = this.base64UrlEncode(iv);

        const keyBytes = this.base64ToBytes(key);
        const payloadBytes = this.stringToBytes(payload);
        
        const encrypted = await this.aesGcmEncrypt(payloadBytes, keyBytes, iv);
        const ciphertextBase64 = this.base64UrlEncode(encrypted.ciphertext);
        const tagBase64 = this.base64UrlEncode(encrypted.tag);

        return headerBase64 + '.' + ivBase64 + '.' + ciphertextBase64 + '.' + tagBase64;
    }

    /**
     * Decrypt JWE token
     * @param {string} jweToken - JWE token
     * @param {string} key - Base64-encoded decryption key
     * @returns {Promise<string>} Decrypted payload
     */
    async decryptJWE(jweToken, key) {
        if (!jweToken) {
            throw new Error('JWE token cannot be null or empty');
        }

        const parts = jweToken.split('.');
        if (parts.length !== 4) {
            throw new Error('Invalid JWE token format - expected 4 parts');
        }

        const [headerB64, ivB64, ciphertextB64, tagB64] = parts;
        
        const headerBytes = this.base64UrlDecode(headerB64);
        const headerJson = this.bytesToString(headerBytes);
        const header = JSON.parse(headerJson);
        
        if (header.alg !== 'dir' || header.enc !== 'A256GCM') {
            throw new Error('Unsupported algorithm');
        }

        const iv = this.base64UrlDecode(ivB64);
        const ciphertext = this.base64UrlDecode(ciphertextB64);
        const tag = this.base64UrlDecode(tagB64);

        const keyBytes = this.base64ToBytes(key);
        const decrypted = await this.aesGcmDecrypt({ ciphertext, tag }, keyBytes, iv);
        
        return this.bytesToString(decrypted);
    }

    /**
     * AES-GCM encryption using Web Crypto API
     * @param {Uint8Array} plaintext - Text to encrypt
     * @param {Uint8Array} key - Encryption key (32 bytes for AES-256)
     * @param {Uint8Array} iv - Initialization vector (12 bytes for GCM)
     * @returns {Promise<Object>} Encrypted data with ciphertext and tag
     */
    async aesGcmEncrypt(plaintext, key, iv) {
        if (key.length !== 32) {
            throw new Error('Invalid key size: ' + key.length + ' bytes. Expected exactly 32 bytes (256 bits) for AES-256');
        }

        if (typeof crypto === 'undefined' || !crypto.subtle) {
            throw new Error('Web Crypto API not available');
        }

        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            'AES-GCM',
            false,
            ['encrypt']
        );
        
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            cryptoKey,
            plaintext
        );
        
        const encryptedArray = new Uint8Array(encrypted);
        const tagLength = 16;
        const ciphertext = encryptedArray.slice(0, -tagLength);
        const tag = encryptedArray.slice(-tagLength);
        
        return { ciphertext, tag };
    }

    /**
     * AES-GCM decryption using Web Crypto API
     * @param {Object} encrypted - Encrypted data with ciphertext and tag
     * @param {Uint8Array} key - Decryption key (32 bytes for AES-256)
     * @param {Uint8Array} iv - Initialization vector (12 bytes for GCM)
     * @returns {Promise<Uint8Array>} Decrypted data
     */
    async aesGcmDecrypt(encrypted, key, iv) {
        if (key.length !== 32) {
            throw new Error('Invalid key size: ' + key.length + ' bytes. Expected exactly 32 bytes (256 bits) for AES-256');
        }

        if (typeof crypto === 'undefined' || !crypto.subtle) {
            throw new Error('Web Crypto API not available');
        }

        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            'AES-GCM',
            false,
            ['decrypt']
        );
        
        const combined = new Uint8Array(encrypted.ciphertext.length + encrypted.tag.length);
        combined.set(encrypted.ciphertext);
        combined.set(encrypted.tag, encrypted.ciphertext.length);
        
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            cryptoKey,
            combined
        );
        
        return new Uint8Array(decrypted);
    }

    /**
     * HMAC-SHA256 using crypto-js
     * @param {string} data - Data to sign
     * @param {Uint8Array} key - Signing key
     * @returns {Promise<Uint8Array>} HMAC result
     */
    async hmacSign(data, key) {
        if (!CryptoJS) {
            throw new Error('crypto-js library not available');
        }

        const keyWords = CryptoJS.lib.WordArray.create(key);
        const dataWords = CryptoJS.enc.Utf8.parse(data);
        const hmac = CryptoJS.HmacSHA256(dataWords, keyWords);
        
        const words = hmac.words;
        const sigBytes = hmac.sigBytes;
        const result = new Uint8Array(sigBytes);
        
        for (let i = 0; i < sigBytes; i++) {
            const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            result[i] = byte;
        }
        
        return result;
    }

    /**
     * Base64URL encode
     * @param {string|Uint8Array} input - Input to encode
     * @returns {string} Base64URL encoded string
     */
    base64UrlEncode(input) {
        let str;
        if (input instanceof Uint8Array) {
            let charArray = [];
            for (let i = 0; i < input.length; i++) {
                charArray.push(String.fromCharCode(input[i]));
            }
            str = charArray.join('');
        } else {
            str = input;
        }
        
        if (CryptoJS && CryptoJS.enc && CryptoJS.enc.Base64) {
            const base64 = CryptoJS.enc.Latin1.parse(str).toString(CryptoJS.enc.Base64);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
        
        if (typeof btoa !== 'undefined') {
            return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
        
        throw new Error('Base64 encoding not available - btoa and crypto-js both unavailable');
    }

    /**
     * Base64URL decode
     * @param {string} str - Base64URL string to decode
     * @returns {Uint8Array} Decoded bytes
     */
    base64UrlDecode(str) {
        while (str.length % 4) {
            str += '=';
        }
        
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        
        let decoded;
        
        if (CryptoJS && CryptoJS.enc && CryptoJS.enc.Base64) {
            const words = CryptoJS.enc.Base64.parse(str);
            const decodedStr = words.toString(CryptoJS.enc.Latin1);
            decoded = decodedStr;
        } else if (typeof atob !== 'undefined') {
            decoded = atob(str);
        } else {
            throw new Error('Base64 decoding not available - atob and crypto-js both unavailable');
        }
        
        const result = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
            result[i] = decoded.charCodeAt(i);
        }
        return result;
    }

    /**
     * Convert base64 to bytes
     * @param {string} base64 - Base64 string
     * @returns {Uint8Array} Bytes
     */
    base64ToBytes(base64) {
        let decoded;
        
        if (CryptoJS && CryptoJS.enc && CryptoJS.enc.Base64) {
            const words = CryptoJS.enc.Base64.parse(base64);
            const decodedStr = words.toString(CryptoJS.enc.Latin1);
            decoded = decodedStr;
        } else if (typeof atob !== 'undefined') {
            decoded = atob(base64);
        } else {
            throw new Error('Base64 decoding not available - atob and crypto-js both unavailable');
        }
        
        const result = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
            result[i] = decoded.charCodeAt(i);
        }
        return result;
    }

    /**
     * Convert string to bytes (UTF-8)
     * @param {string} str - String
     * @returns {Uint8Array} Bytes
     */
    stringToBytes(str) {
        if (typeof TextEncoder !== 'undefined') {
            return new TextEncoder().encode(str);
        }
        
        const utf8 = [];
        for (let i = 0; i < str.length; i++) {
            let charcode = str.charCodeAt(i);
            if (charcode < 0x80) utf8.push(charcode);
            else if (charcode < 0x800) {
                utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
            } else if (charcode < 0xd800 || charcode >= 0xe000) {
                utf8.push(0xe0 | (charcode >> 12), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
            } else {
                i++;
                charcode = 0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
                utf8.push(0xf0 | (charcode >> 18), 0x80 | ((charcode >> 12) & 0x3f), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
            }
        }
        return new Uint8Array(utf8);
    }

    /**
     * Convert bytes to string (UTF-8)
     * @param {Uint8Array} bytes - Bytes
     * @returns {string} String
     */
    bytesToString(bytes) {
        if (typeof TextDecoder !== 'undefined') {
            return new TextDecoder().decode(bytes);
        }
        
        let result = '';
        let i = 0;
        while (i < bytes.length) {
            let c = bytes[i++];
            if (c > 127) {
                if (c > 191 && c < 224) {
                    c = (c & 31) << 6 | bytes[i++] & 63;
                } else if (c > 223 && c < 240) {
                    c = (c & 15) << 12 | (bytes[i++] & 63) << 6 | bytes[i++] & 63;
                } else {
                    c = (c & 7) << 18 | (bytes[i++] & 63) << 12 | (bytes[i++] & 63) << 6 | bytes[i++] & 63;
                }
            }
            result += String.fromCharCode(c);
        }
        return result;
    }

    /**
     * Generate random bytes
     * @param {number} length - Number of bytes
     * @returns {Uint8Array} Random bytes
     */
    generateRandomBytes(length) {
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            try {
                return crypto.getRandomValues(new Uint8Array(length));
            } catch (e) {
                console.warn('crypto.getRandomValues failed, using fallback:', e.message);
            }
        }
        
        if (CryptoJS && CryptoJS.lib && CryptoJS.lib.WordArray) {
            const random = CryptoJS.lib.WordArray.random(length);
            const words = random.words;
            const result = new Uint8Array(length);
            for (let i = 0; i < length; i++) {
                const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                result[i] = byte;
            }
            return result;
        }
        
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = Math.floor(Math.random() * 256);
        }
        return bytes;
    }

    /**
     * Get hex preview of bytes (first and last few bytes)
     * @param {Uint8Array} bytes - Bytes to preview
     * @param {number} previewLength - Number of bytes to show from start and end
     * @returns {string} Hex preview string
     */
    getHexPreview(bytes, previewLength = 8) {
        if (!bytes || bytes.length === 0) return 'empty';
        if (bytes.length <= previewLength * 2) {
            return this.bytesToHex(bytes);
        }
        const start = this.bytesToHex(bytes.slice(0, previewLength));
        const end = this.bytesToHex(bytes.slice(-previewLength));
        return start + '...' + end + ' (' + bytes.length + ' bytes total)';
    }

    /**
     * Convert bytes to hex string
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {string} Hex string
     */
    bytesToHex(bytes) {
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            const h = bytes[i].toString(16).padStart(2, '0');
            hex += h;
        }
        return hex;
    }

    /**
     * Format process step for logging and display
     * @param {string} stepName - Name of the step
     * @param {Object} data - Data to format
     * @returns {Object} Formatted step info
     */
    formatProcessStep(stepName, data) {
        const step = {
            name: stepName,
            timestamp: new Date().toISOString(),
            data: {}
        };

        // Format different data types
        for (const key in data) {
            if (data.hasOwnProperty(key)) {
                const value = data[key];
                if (value instanceof Uint8Array) {
                    step.data[key] = {
                        type: 'Uint8Array',
                        length: value.length,
                        hexPreview: this.getHexPreview(value),
                        hexFull: value.length <= 64 ? this.bytesToHex(value) : this.getHexPreview(value, 32)
                    };
                } else if (typeof value === 'string') {
                    step.data[key] = {
                        type: 'string',
                        value: value,
                        length: value.length,
                        preview: value.length > 100 ? value.substring(0, 100) + '...' : value
                    };
                } else if (typeof value === 'object' && value !== null) {
                    step.data[key] = {
                        type: 'object',
                        value: JSON.stringify(value),
                        preview: JSON.stringify(value).length > 200 ? JSON.stringify(value).substring(0, 200) + '...' : JSON.stringify(value)
                    };
                } else {
                    step.data[key] = {
                        type: typeof value,
                        value: value
                    };
                }
            }
        }

        return step;
    }
}

module.exports = CryptoTestService;

