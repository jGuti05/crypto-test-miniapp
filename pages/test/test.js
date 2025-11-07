/**
 * Crypto Test Page - Comprehensive Web Crypto API Test Runner
 * 
 * This page runs all crypto tests and displays detailed results organized by category.
 */

const CryptoTestService = require('../../shared/services/CryptoTestService');

Page({
  data: {
    // Environment info
    environmentInfo: null,
    
    // Test results organized by category
    basicTests: [],
    cryptoJSTests: [],
    webCryptoAPITests: [],
    fullFlowTests: [],
    
    // Summary
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    
    // Test state
    isRunning: false,
    lastRunTime: null
  },

  onLoad() {
    console.log('[Test Page] Page loaded, starting tests...');
    this.runAllTests();
  },

  /**
   * Run all crypto tests
   */
  async runAllTests() {
    if (this.data.isRunning) {
      console.log('[Test Page] Tests already running, skipping...');
      return;
    }

    this.setData({ isRunning: true, lastRunTime: null });
    console.log('[Test Page] Starting all tests...');

    const testService = new CryptoTestService({
      salt: 'test-salt-2024',
      iterations: 10000
    });

    // Get environment info first
    const environmentInfo = await testService.getEnvironmentInfo();
    this.setData({ environmentInfo });

    // Run all tests
    const basicTests = [];
    const cryptoJSTests = [];
    const webCryptoAPITests = [];
    const fullFlowTests = [];

    // Basic API Tests
    console.log('[Test Page] Running basic API tests...');
    basicTests.push(await testService.testWebCryptoAvailability());
    basicTests.push(await testService.testGetRandomValues());

    // crypto-js Tests (should work everywhere)
    console.log('[Test Page] Running crypto-js tests...');
    cryptoJSTests.push(await testService.testPBKDF2());
    cryptoJSTests.push(await testService.testHMAC());

    // Web Crypto API Tests (expected to fail on iOS release)
    console.log('[Test Page] Running Web Crypto API tests...');
    webCryptoAPITests.push(await testService.testAESGCMKeyImport());
    webCryptoAPITests.push(await testService.testAESGCMEncryption());
    webCryptoAPITests.push(await testService.testAESGCMDecryption());

    // Full Flow Tests
    console.log('[Test Page] Running full flow tests...');
    fullFlowTests.push(await testService.testFullJWEEncryption());
    fullFlowTests.push(await testService.testFullJWEDecryption());
    fullFlowTests.push(await testService.testFullEncryptDecryptCycle());

    // Calculate summary
    const allTests = [...basicTests, ...cryptoJSTests, ...webCryptoAPITests, ...fullFlowTests];
    const passedTests = allTests.filter(t => t.passed).length;
    const failedTests = allTests.filter(t => !t.passed).length;

    // Format process steps for display
    const formatProcessSteps = (test) => {
      if (test.processSteps && test.processSteps.length > 0) {
        test.processStepsFormatted = this.formatAllProcessSteps(test.processSteps);
      }
      return test;
    };

    const formattedBasicTests = basicTests.map(formatProcessSteps);
    const formattedCryptoJSTests = cryptoJSTests.map(formatProcessSteps);
    const formattedWebCryptoAPITests = webCryptoAPITests.map(formatProcessSteps);
    const formattedFullFlowTests = fullFlowTests.map(formatProcessSteps);

    // Log results to console
    console.log('[Test Page] Test Results Summary:');
    console.log('[Test Page] Total:', allTests.length);
    console.log('[Test Page] Passed:', passedTests);
    console.log('[Test Page] Failed:', failedTests);
    console.log('[Test Page] Failed tests:', allTests.filter(t => !t.passed).map(t => t.name));

    // Update page data
    this.setData({
      basicTests: formattedBasicTests,
      cryptoJSTests: formattedCryptoJSTests,
      webCryptoAPITests: formattedWebCryptoAPITests,
      fullFlowTests: formattedFullFlowTests,
      totalTests: allTests.length,
      passedTests,
      failedTests,
      isRunning: false,
      lastRunTime: new Date().toLocaleTimeString()
    });

    console.log('[Test Page] All tests completed');
  },

  /**
   * Re-run all tests
   */
  onRerunTests() {
    console.log('[Test Page] Re-running all tests...');
    this.runAllTests();
  },

  /**
   * Format error for display
   */
  formatError(error) {
    if (!error) return 'No error details';
    
    let errorText = error.message || 'Unknown error';
    if (error.type) {
      errorText += ' (Type: ' + error.type + ')';
    }
    if (error.stack) {
      errorText += '\n\nStack trace:\n' + error.stack;
    }
    return errorText;
  },

  /**
   * Format process step data for display
   */
  formatProcessStepData(step) {
    if (!step || !step.data) return '';
    
    let formatted = step.name + ':\n';
    for (const key in step.data) {
      if (step.data.hasOwnProperty(key)) {
        const dataItem = step.data[key];
        formatted += '  ' + key + ': ';
        
        if (dataItem.type === 'Uint8Array') {
          formatted += '[' + dataItem.type + ', ' + dataItem.length + ' bytes, hex: ' + dataItem.hexPreview + ']';
        } else if (dataItem.type === 'string') {
          formatted += '[' + dataItem.type + ', ' + dataItem.length + ' chars] ' + dataItem.preview;
        } else if (dataItem.type === 'object') {
          formatted += '[' + dataItem.type + '] ' + dataItem.preview;
        } else {
          formatted += '[' + dataItem.type + '] ' + dataItem.value;
        }
        formatted += '\n';
      }
    }
    return formatted;
  },

  /**
   * Format all process steps for display
   */
  formatAllProcessSteps(processSteps) {
    if (!processSteps || processSteps.length === 0) return '';
    
    let formatted = '';
    for (let i = 0; i < processSteps.length; i++) {
      formatted += this.formatProcessStepData(processSteps[i]);
      if (i < processSteps.length - 1) {
        formatted += '\n';
      }
    }
    return formatted;
  }
});

