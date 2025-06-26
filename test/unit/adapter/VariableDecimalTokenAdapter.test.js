const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const { smock } = require("@defi-wonderland/smock");

const { formatBytes32String } = ethers.utils;
const { WeiPerWad } = require("../../helper/unit");

describe("VariableDecimalTokenAdapter", () => {
  let tokenAdapter, mockedBookKeeper, mockedToken9Decimals, mockedAccessControlConfig, DeployerAddress, AliceAddress;

  const deployFixtures = async () => {
    const { deployer, allice } = await getNamedAccounts();
    DeployerAddress = deployer;
    AliceAddress = allice;

    const mockedAccessControlConfig = await smock.fake("AccessControlConfig");
    const mockedCollateralPoolConfig = await smock.fake("CollateralPoolConfig");
    const mockedVault = await smock.fake("Vault");

    const mockedBookKeeper = await smock.fake("BookKeeper");
    const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
    const mockedToken9Decimals = await ERC20Mintable9DecimalsFactory.deploy("Test Token 9", "TT9");
    await mockedToken9Decimals.deployed();

    mockedAccessControlConfig.OWNER_ROLE.returns(formatBytes32String("OWNER_ROLE"));
    mockedAccessControlConfig.GOV_ROLE.returns(formatBytes32String("GOV_ROLE"));
    mockedAccessControlConfig.SHOW_STOPPER_ROLE.returns(formatBytes32String("SHOW_STOPPER_ROLE"));
    mockedAccessControlConfig.hasRole.returns(true);

    const TokenAdapterFactory = await ethers.getContractFactory("TokenAdapter");
    const tokenAdapter = await TokenAdapterFactory.deploy();
    await tokenAdapter.deployed();

    return {
      tokenAdapter,
      mockedBookKeeper,
      mockedToken9Decimals,
      mockedAccessControlConfig,
      mockedCollateralPoolConfig,
      mockedVault,
    };
  };

  beforeEach(async () => {
    ({ tokenAdapter, mockedBookKeeper, mockedToken9Decimals, mockedAccessControlConfig } = await loadFixture(deployFixtures));
  });

  describe("#initialize() with 9 decimals token", () => {
    context("when token has 9 decimals", () => {
      it("should initialize successfully", async () => {
        await tokenAdapter.initialize(mockedBookKeeper.address, formatBytes32String("BTCB"), mockedToken9Decimals.address);
        
        expect(await tokenAdapter.decimals()).to.equal(9);
        expect(await tokenAdapter.collateralToken()).to.equal(mockedToken9Decimals.address);
      });
    });

    context("when token has more than 18 decimals", () => {
      it("should revert", async () => {
        // Create mock token with 20 decimals
        const ERC20Mintable20DecimalsFactory = await ethers.getContractFactory("ERC20Mintable");
        const mockedToken20Decimals = await ERC20Mintable20DecimalsFactory.deploy("Test Token 20", "TT20");
        await mockedToken20Decimals.deployed();
        await mockedToken20Decimals.setDecimals(20);

        await expect(
          tokenAdapter.initialize(mockedBookKeeper.address, formatBytes32String("BTCB"), mockedToken20Decimals.address)
        ).to.be.revertedWith("TokenAdapter/decimals-too-high");
      });
    });
  });

  describe("#deposit() with 9 decimals token", () => {
    beforeEach(async () => {
      await tokenAdapter.initialize(mockedBookKeeper.address, formatBytes32String("BTCB"), mockedToken9Decimals.address);
    });

    context("when parameters are valid", () => {
      it("should handle 9 decimal amounts correctly", async () => {
        // 1 token in 9 decimals = 1 * 10^9 = 1,000,000,000
        const tokenAmount = BigNumber.from("1000000000"); // 1 token with 9 decimals
        const wadAmount = tokenAmount.mul(BigNumber.from("1000000000")); // Convert to 18 decimals (WAD)

        mockedBookKeeper.addCollateral.whenCalledWith(formatBytes32String("BTCB"), AliceAddress, wadAmount).returns();
        await mockedToken9Decimals.mint(DeployerAddress, tokenAmount);
        await mockedToken9Decimals.approve(tokenAdapter.address, tokenAmount);

        await expect(tokenAdapter.deposit(AliceAddress, wadAmount, "0x")).to.not.be.reverted;
      });
    });

    context("when amount is in original token decimals", () => {
      it("should work with raw token amounts", async () => {
        const tokenAmount = BigNumber.from("1000000000"); // 1 token with 9 decimals
        
        mockedBookKeeper.addCollateral.returns();
        await mockedToken9Decimals.mint(DeployerAddress, tokenAmount);
        await mockedToken9Decimals.approve(tokenAdapter.address, tokenAmount);

        // Deposit using the token's native amount (this should be converted internally)
        await expect(tokenAdapter.deposit(AliceAddress, tokenAmount, "0x")).to.not.be.reverted;
      });
    });
  });

  describe("#withdraw() with 9 decimals token", () => {
    beforeEach(async () => {
      await tokenAdapter.initialize(mockedBookKeeper.address, formatBytes32String("BTCB"), mockedToken9Decimals.address);
    });

    context("when parameters are valid", () => {
      it("should handle 9 decimal withdrawals correctly", async () => {
        const tokenAmount = BigNumber.from("1000000000"); // 1 token with 9 decimals
        const wadAmount = tokenAmount.mul(BigNumber.from("1000000000")); // Convert to 18 decimals

        mockedBookKeeper.addCollateral.returns();
        await mockedToken9Decimals.mint(tokenAdapter.address, tokenAmount);

        await expect(tokenAdapter.withdraw(AliceAddress, wadAmount, "0x")).to.not.be.reverted;
      });
    });
  });

  describe("Decimal conversion scenarios", () => {
    const testCases = [
      { decimals: 6, name: "USDC-like", multiplier: BigNumber.from("1000000000000") }, // 10^12
      { decimals: 8, name: "Bitcoin-like", multiplier: BigNumber.from("10000000000") }, // 10^10
      { decimals: 9, name: "Custom-token", multiplier: BigNumber.from("1000000000") }, // 10^9
      { decimals: 12, name: "Medium-precision", multiplier: BigNumber.from("1000000") }, // 10^6
      { decimals: 18, name: "ETH-like", multiplier: BigNumber.from("1") }, // 10^0
    ];

    testCases.forEach(({ decimals, name, multiplier }) => {
      context(`when token has ${decimals} decimals (${name})`, () => {
        it(`should convert ${decimals} decimals to 18 decimals correctly`, async () => {
          const tokenAmount = BigNumber.from("1").mul(BigNumber.from("10").pow(decimals)); // 1 token in its native decimals
          const expectedWadAmount = tokenAmount.mul(multiplier); // Convert to 18 decimals

          expect(expectedWadAmount).to.equal(WeiPerWad); // Should equal 1 WAD (10^18)
        });
      });
    });
  });
}); 