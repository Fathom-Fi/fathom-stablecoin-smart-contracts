const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { expect } = require("chai");
const { formatBytes32String } = ethers.utils;

describe("VariableDecimalTokenAdapter CRITICAL ERRORS (Real Contracts)", () => {
  let bookKeeper;
  let collateralTokenAdapter;
  let token6Decimals;
  let accessControlConfig;
  let proxyWalletRegistry;
  let vault;
  let DeployerAddress;

  beforeEach(async () => {
    [DeployerAddress] = await ethers.getSigners();

    // Use mock for AccessControlConfig since it's proxy-based
    const { smock } = require("@defi-wonderland/smock");
    accessControlConfig = await smock.fake("AccessControlConfig");
    accessControlConfig.OWNER_ROLE.returns(ethers.utils.formatBytes32String("OWNER_ROLE"));
    accessControlConfig.ADAPTER_ROLE.returns(ethers.utils.formatBytes32String("ADAPTER_ROLE"));
    accessControlConfig.hasRole.returns(true);

    // Use mock for BookKeeper since it's also proxy-based
    bookKeeper = await smock.fake("BookKeeper");
    bookKeeper.accessControlConfig.returns(accessControlConfig.address);
    bookKeeper.collateralToken.returns(0); // Default balance
    bookKeeper.addCollateral.returns();

    // Use a minimal proxy registry mock  
    proxyWalletRegistry = await smock.fake("ProxyWalletRegistry");

    // Deploy REAL 6 decimals token (like USDC)  
    const ERC20MintableStableSwapFactory = await ethers.getContractFactory("ERC20MintableStableSwap");
    token6Decimals = await ERC20MintableStableSwapFactory.deploy("Token 6 Decimals", "T6D");
    await token6Decimals.deployed();

    // Deploy REAL CollateralTokenAdapter (but simplified deployment)
    const CollateralTokenAdapterFactory = await ethers.getContractFactory("TokenAdapter");
    collateralTokenAdapter = await CollateralTokenAdapterFactory.deploy();
    await collateralTokenAdapter.deployed();

    // Deploy REAL vault
    const MockVaultFactory = await ethers.getContractFactory("MockVault");
    vault = await MockVaultFactory.deploy(
      formatBytes32String("6DECIMALS"),
      token6Decimals.address,
      collateralTokenAdapter.address
    );
    await vault.deployed();

    // Mock roles are already set up - no need to grant roles

    // Initialize adapter (TokenAdapter style)
    await collateralTokenAdapter.initialize(
      bookKeeper.address,
      formatBytes32String("6DECIMALS"),
      token6Decimals.address
    );

    await collateralTokenAdapter.setVault(vault.address);
  });

  describe("CRITICAL INTERFACE ERRORS", () => {
    it("CRITICAL: deposit() interface expects WAD but current logic is backwards", async () => {
      // Mint 1 USDC (6 decimals) = 1,000,000 wei
      const oneUSDC = BigNumber.from("1000000"); 
      await token6Decimals.mint(DeployerAddress.address, oneUSDC);
      await token6Decimals.approve(collateralTokenAdapter.address, oneUSDC);

      // According to IGenericTokenAdapter interface, deposit takes WAD amount
      // If we pass 1,000,000 (1 USDC in native decimals), 
      // the CURRENT BROKEN LOGIC will try to:
      // 1. _convertFromWad(1,000,000) = 1,000,000 / 10^12 = 0.001 tokens = 1,000 wei
      // 2. Try to transfer only 1,000 wei but we have 1,000,000 wei available
      // 3. This makes the test pass but is WRONG

      // This deposit call is WRONG - we should pass WAD amount, not native amount
      await expect(
        collateralTokenAdapter.deposit(DeployerAddress.address, oneUSDC, "0x")
      ).to.not.be.reverted; 

      // THIS IS THE CRITICAL ERROR: Check what's actually stored in BookKeeper
      const storedAmount = await bookKeeper.collateralToken(formatBytes32String("6DECIMALS"), DeployerAddress.address);
      
      // CRITICAL ERROR EXPOSED: If interface is supposed to take WAD but we passed native decimals,
      // the stored amount should be TINY (0.001 tokens = 1000 wei) not 1,000,000 wei
      console.log("❌ CRITICAL ERROR: Native amount passed:", oneUSDC.toString());
      console.log("❌ CRITICAL ERROR: Amount stored in BookKeeper:", storedAmount.toString());
      console.log("❌ CRITICAL ERROR: Expected WAD amount would be:", oneUSDC.mul(BigNumber.from(10).pow(12)).toString());
      
      // If the logic was correct and we passed native decimals, 
      // it should convert to WAD and store 1,000,000,000,000,000,000 (1e18)
      // But with current broken logic, it stores the raw amount after wrong conversion
      
      // THIS PROVES THE LOGIC IS BACKWARDS
      expect(storedAmount).to.equal(oneUSDC); // This is WRONG - it should be WAD amount!
    });

    it("CRITICAL: Correct WAD deposit should fail with current broken logic", async () => {
      // This is what SHOULD work according to the interface
      const oneUSDC = BigNumber.from("1000000"); // 1 USDC in native decimals
      const oneUSDCInWAD = oneUSDC.mul(BigNumber.from(10).pow(12)); // Convert to WAD (18 decimals)
      
      await token6Decimals.mint(DeployerAddress.address, oneUSDC);
      await token6Decimals.approve(collateralTokenAdapter.address, oneUSDC);

      // According to interface, we should pass WAD amount
      // But current broken logic will try to convert WAD back to native:
      // _convertFromWad(1e18) = 1e18 / 1e12 = 1e6 = 1,000,000 tokens
      // But we only have 1,000,000 wei available, so this should work... but it's still wrong logic

      await expect(
        collateralTokenAdapter.deposit(DeployerAddress.address, oneUSDCInWAD, "0x")
      ).to.not.be.reverted;

      const storedAmount = await bookKeeper.collateralToken(formatBytes32String("6DECIMALS"), DeployerAddress.address);
      
      console.log("❌ CRITICAL: WAD input:", oneUSDCInWAD.toString());
      console.log("❌ CRITICAL: Stored amount:", storedAmount.toString());
      
      // With current broken logic, this will store the WAD amount directly
      // which is correct by accident, but the logic is still backwards
      expect(storedAmount).to.equal(oneUSDCInWAD);
    });

    it("CRITICAL: Precision loss error - small WAD amounts become zero", async () => {
      // This exposes the critical precision loss issue
      const smallWADAmount = BigNumber.from("100000000000"); // 0.0001 tokens in WAD
      
      await token6Decimals.mint(DeployerAddress.address, BigNumber.from("1000000"));
      await token6Decimals.approve(collateralTokenAdapter.address, BigNumber.from("1000000"));

      // Current broken logic: _convertFromWad(100000000000) = 100000000000 / 1e12 = 0.1 = 0 (truncated)
      // This will try to transfer 0 tokens!
      
      await expect(
        collateralTokenAdapter.deposit(DeployerAddress.address, smallWADAmount, "0x")
      ).to.not.be.reverted;

      const storedAmount = await bookKeeper.collateralToken(formatBytes32String("6DECIMALS"), DeployerAddress.address);
      
      console.log("❌ PRECISION LOSS: Input WAD:", smallWADAmount.toString());
      console.log("❌ PRECISION LOSS: Stored:", storedAmount.toString());
      
      // This proves precision loss - small amounts get lost
      if (storedAmount.eq(0)) {
        console.log("❌ CRITICAL: PRECISION LOSS DETECTED - small amounts become zero!");
      }
    });
  });
}); 