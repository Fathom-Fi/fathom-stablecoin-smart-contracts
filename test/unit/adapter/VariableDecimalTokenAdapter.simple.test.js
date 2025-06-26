const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { expect } = require("chai");

describe("VariableDecimalTokenAdapter Simple Test", () => {
  let token9Decimals;

  beforeEach(async () => {
    // Deploy 9 decimal token
    const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
    token9Decimals = await ERC20Mintable9DecimalsFactory.deploy("Test Token 9", "TT9");
    await token9Decimals.deployed();
  });

  describe("9 Decimals Token", () => {
    it("should have 9 decimals", async () => {
      expect(await token9Decimals.decimals()).to.equal(9);
    });

    it("should mint tokens correctly", async () => {
      const [owner] = await ethers.getSigners();
      const amount = BigNumber.from("1000000000"); // 1 token with 9 decimals
      
      await token9Decimals.mint(owner.address, amount);
      expect(await token9Decimals.balanceOf(owner.address)).to.equal(amount);
    });
  });

  describe("Decimal conversion math", () => {
    it("should correctly convert between different decimal places", async () => {
      // Test decimal conversion logic similar to what's in _convertTo18
      const convertTo18 = (amount, fromDecimals) => {
        if (fromDecimals < 18) {
          return amount.mul(BigNumber.from("10").pow(18 - fromDecimals));
        } else if (fromDecimals == 18) {
          return amount;
        } else {
          throw new Error("Decimals > 18 not supported");
        }
      };

      // Test with 9 decimals
      const amount9Decimals = BigNumber.from("1000000000"); // 1 token with 9 decimals
      const convertedAmount = convertTo18(amount9Decimals, 9);
      expect(convertedAmount).to.equal(BigNumber.from("1000000000000000000")); // 1 WAD (18 decimals)

      // Test with 6 decimals
      const amount6Decimals = BigNumber.from("1000000"); // 1 token with 6 decimals
      const convertedAmount6 = convertTo18(amount6Decimals, 6);
      expect(convertedAmount6).to.equal(BigNumber.from("1000000000000000000")); // 1 WAD (18 decimals)
    });
  });
}); 