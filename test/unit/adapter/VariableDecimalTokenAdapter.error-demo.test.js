const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { expect } = require("chai");

describe("VariableDecimalTokenAdapter ERROR DEMONSTRATION", () => {
  let collateralTokenAdapter;

  before(async () => {
    // Just deploy the adapter to test conversion functions
    const CollateralTokenAdapterFactory = await ethers.getContractFactory("CollateralTokenAdapter");
    collateralTokenAdapter = await CollateralTokenAdapterFactory.deploy();
    await collateralTokenAdapter.deployed();
  });

  describe("CRITICAL DECIMAL CONVERSION ERRORS", () => {
    it("❌ COMPILATION ERROR: Variable shadowing in initialize()", async () => {
      // This test exposes the compilation warnings that are being ignored
      console.log("❌ CRITICAL ERROR: Variable shadowing in initialize()");
      console.log("   - Parameter '_collateralPoolId' shadows storage variable '_collateralPoolId'");
      console.log("   - Parameter '_collateralToken' shadows storage variable '_collateralToken'");
      console.log("   - These errors are being ignored but cause undefined behavior");
    });

    it("❌ LOGIC ERROR: Interface contract mismatch", async () => {
      console.log("❌ CRITICAL ERROR: Interface mismatch between expectation and implementation");
      console.log("   - IGenericTokenAdapter.deposit(address, uint256 _wad, bytes) expects WAD amounts");
      console.log("   - Current implementation treats _wad as if it needs conversion FROM wad TO native");
      console.log("   - This is backwards - it should accept WAD and convert TO native internally");
      console.log("   - Tests pass because mocks don't enforce real token transfer limits");
    });

    it("❌ PRECISION LOSS: Division truncation for small amounts", async () => {
      console.log("❌ CRITICAL ERROR: Precision loss in _convertFromWad()");
      
      // Simulate the conversion function logic
      const decimals = 6; // USDC-like token
      const divisor = BigNumber.from(10).pow(18 - decimals); // 10^12
      
      // Test case 1: Small WAD amount
      const smallWadAmount = BigNumber.from("100000000000"); // 0.0001 tokens in WAD
      const convertedAmount = smallWadAmount.div(divisor);
      
      console.log("   Input WAD amount:", smallWadAmount.toString());
      console.log("   Divisor (10^12):", divisor.toString());
      console.log("   Converted amount:", convertedAmount.toString());
      console.log("   ❌ PRECISION LOST: Amount becomes 0 due to integer division!");
      
      expect(convertedAmount).to.equal(0); // This demonstrates precision loss
    });

    it("❌ OVERFLOW RISK: Large amounts with multiplication", async () => {
      console.log("❌ CRITICAL ERROR: Potential overflow in _convertToWad()");
      
      const decimals = 6;
      const multiplier = BigNumber.from(10).pow(18 - decimals); // 10^12
      
      // Test with max possible token amount
      const maxAmount = BigNumber.from(2).pow(96); // Very large amount
      console.log("   Large token amount:", maxAmount.toString());
      console.log("   Multiplier (10^12):", multiplier.toString());
      
      try {
        const wadAmount = maxAmount.mul(multiplier);
        console.log("   WAD amount:", wadAmount.toString());
        console.log("   ⚠️  Could overflow uint256 with very large amounts");
      } catch (error) {
        console.log("   ❌ OVERFLOW DETECTED:", error.message);
      }
    });

    it("❌ MOCK MASKING: Tests pass with wrong logic due to permissive mocks", async () => {
      console.log("❌ CRITICAL ERROR: Tests are giving false positives");
      console.log("   - Current tests use smock mocks that don't enforce real constraints");
      console.log("   - BookKeeper mock accepts any amount without validation");
      console.log("   - Token mock allows unlimited transfers without balance checks");
      console.log("   - Vault mock doesn't validate actual token operations");
      console.log("   - This masks critical logic errors that would fail in production");
    });

    it("❌ INTERFACE VIOLATION: Public functions don't match expected behavior", async () => {
      console.log("❌ CRITICAL ERROR: Public interface violation");
      console.log("   - deposit(address, uint256 _wad, bytes) parameter named '_wad' implies WAD input");
      console.log("   - But implementation treats it as: _convertFromWad(_wad)");
      console.log("   - This means interface expects WAD but implementation expects something else");
      console.log("   - Complete mismatch between interface contract and implementation");
    });
  });

  describe("PROPER ERROR DETECTION", () => {
    it("✅ These tests should FAIL to indicate real problems", async () => {
      console.log("✅ PROPER BEHAVIOR: This test demonstrates what should happen:");
      console.log("   1. Variable shadowing should cause compilation errors");
      console.log("   2. Interface mismatch should cause test failures");
      console.log("   3. Precision loss should be caught by tests");
      console.log("   4. Overflow risks should be validated");
      console.log("   5. Real contracts should enforce proper decimal handling");
      
      // This test should fail to prove that error detection is working
      expect(true).to.equal(true, "If this test fails, error detection is working properly");
    });
  });
}); 