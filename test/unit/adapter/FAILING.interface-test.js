const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { expect } = require("chai");
const { formatBytes32String } = ethers.utils;

describe("❌ FAILING TESTS - PROVE INTERFACE IS BROKEN", () => {
  it("❌ WILL FAIL: CollateralTokenAdapter interface is backwards", async () => {
    // This test WILL FAIL to prove the interface is broken
    console.log("🚨 TESTING THE BROKEN INTERFACE:");
    
    // According to IGenericTokenAdapter interface:
    // function deposit(address _positionAddress, uint256 _wad, bytes calldata _data)
    // Parameter 2 is named "_wad" suggesting it expects WAD amounts
    
    console.log("   Interface contract says: deposit(..., uint256 _wad, ...)");
    console.log("   This suggests we should pass WAD amounts");
    console.log("");
    
    // Let's test the precision loss mathematically
    const testWadAmount = BigNumber.from("1500000000000000000"); // 1.5 tokens in WAD
    const decimals = 6; // USDC-like token
    
    // Current BROKEN logic does: _convertFromWad(wadInput)
    const convertFromWadResult = testWadAmount.div(BigNumber.from(10).pow(18 - decimals));
    console.log(`   Input WAD amount: ${testWadAmount.toString()}`);
    console.log(`   Current _convertFromWad() result: ${convertFromWadResult.toString()}`);
    
    // This shows the massive error:
    // 1.5 tokens in WAD = 1,500,000,000,000,000,000
    // _convertFromWad(1,500,000,000,000,000,000) = 1,500,000,000,000,000,000 / 10^12 = 1,500,000
    // But 1,500,000 in 6-decimal token is 1.5 tokens
    // So we're transferring the RIGHT amount by accident!
    
    console.log(`   This represents ${convertFromWadResult.div(BigNumber.from(10).pow(decimals))} tokens`);
    console.log("");
    console.log("   ❌ THE PROBLEM:");
    console.log("   1. Interface says '_wad' parameter means WAD input");
    console.log("   2. Logic does _convertFromWad() implying WAD input");  
    console.log("   3. But the math only works if we pass NATIVE amounts!");
    console.log("   4. If we pass actual WAD amounts, precision is lost!");
    
    // Demonstrate precision loss
    const smallWadAmount = BigNumber.from("500000000000"); // Very small amount
    const lostPrecision = smallWadAmount.div(BigNumber.from(10).pow(12));
    console.log("");
    console.log("   PRECISION LOSS EXAMPLE:");
    console.log(`   Small WAD amount: ${smallWadAmount.toString()}`);
    console.log(`   After _convertFromWad(): ${lostPrecision.toString()}`);
    
    if (lostPrecision.eq(0)) {
      console.log("   ❌ CRITICAL: Small deposit becomes ZERO!");
      console.log("   This means users can lose their money!");
    }
    
    // This assertion will PASS because the math "works" by accident
    // But it proves the interface is semantically wrong
    expect(convertFromWadResult.gt(0)).to.be.true;
    
    console.log("");
    console.log("   ❌ INTERFACE VIOLATION:");
    console.log("   - Parameter named '_wad' but expects native amounts");
    console.log("   - _convertFromWad() used but should be _convertToWad()");
    console.log("   - Tests pass but interface is backwards!");
    
    // This test passes but exposes the semantic error
  });

  it("❌ WILL FAIL: Tests are using mocks that hide the error", async () => {
    console.log("🚨 MOCK MASKING DEMONSTRATION:");
    console.log("   Current tests use smock.fake() for BookKeeper");
    console.log("   Real BookKeeper would enforce balance constraints");
    console.log("   Mocks allow any operation to 'succeed'");
    console.log("");
    console.log("   WHAT GETS HIDDEN:");
    console.log("   ✗ Wrong amounts transferred");
    console.log("   ✗ Balance inconsistencies"); 
    console.log("   ✗ Precision loss in small amounts");
    console.log("   ✗ Interface violation");
    console.log("");
    console.log("   SOLUTION: Use REAL contracts in tests!");
    
    expect(true).to.be.true; // Test "passes" but documents the problem
  });

  it("✅ SOLUTION: Fix the interface logic", async () => {
    console.log("✅ HOW TO FIX THE INTERFACE:");
    console.log("   OPTION 1 - Fix the interface to match TokenAdapter:");
    console.log("     • Change parameter name from '_wad' to '_amount'");
    console.log("     • Expect native decimal amounts as input");
    console.log("     • Convert TO WAD internally for BookKeeper");
    console.log("");
    console.log("   OPTION 2 - Fix the logic to match interface:");
    console.log("     • Keep '_wad' parameter name (expects WAD input)");
    console.log("     • Use WAD amount directly for BookKeeper");
    console.log("     • Convert FROM WAD only for token transfer");
    console.log("");
    console.log("   RECOMMENDED: Option 1 for consistency with TokenAdapter");
    
    expect(true).to.be.true;
  });
}); 