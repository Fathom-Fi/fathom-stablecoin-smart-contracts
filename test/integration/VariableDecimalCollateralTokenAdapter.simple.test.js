const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { formatBytes32String } = ethers.utils;
const { expect } = require("chai");

describe("VariableDecimalCollateralTokenAdapter SIMPLE Integration", () => {
  let bookKeeper;
  let accessControlConfig;
  let vault;
  let collateralTokenAdapter;
  let token9Decimals;
  let DeployerAddress;

  beforeEach(async () => {
    [DeployerAddress] = await ethers.getSigners();

    // Deploy real AccessControlConfig
    const AccessControlConfigFactory = await ethers.getContractFactory("AccessControlConfig");
    accessControlConfig = await AccessControlConfigFactory.deploy();
    await accessControlConfig.deployed();

    // Deploy real BookKeeper
    const BookKeeperFactory = await ethers.getContractFactory("BookKeeper");
    bookKeeper = await BookKeeperFactory.deploy();
    await bookKeeper.deployed();

    await bookKeeper.initialize(accessControlConfig.address);

    // Deploy 9 decimals token
    const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
    token9Decimals = await ERC20Mintable9DecimalsFactory.deploy("Token 9 Decimals", "T9D");
    await token9Decimals.deployed();

    // Deploy CollateralTokenAdapter
    const CollateralTokenAdapterFactory = await ethers.getContractFactory("CollateralTokenAdapter");
    collateralTokenAdapter = await CollateralTokenAdapterFactory.deploy();
    await collateralTokenAdapter.deployed();

    // Deploy vault
    const MockVaultFactory = await ethers.getContractFactory("MockVault");
    vault = await MockVaultFactory.deploy(
      formatBytes32String("9DECIMALS"),
      token9Decimals.address,
      collateralTokenAdapter.address
    );
    await vault.deployed();

    // Set up roles
    await accessControlConfig.grantRole(await accessControlConfig.OWNER_ROLE(), DeployerAddress.address);
    await accessControlConfig.grantRole(await accessControlConfig.ADAPTER_ROLE(), collateralTokenAdapter.address);

    // Initialize adapter
    await collateralTokenAdapter.initialize(
      bookKeeper.address,
      formatBytes32String("9DECIMALS"),
      token9Decimals.address,
      DeployerAddress.address // Use deployer as proxy factory for simplicity
    );

    await collateralTokenAdapter.setVault(vault.address);
    await collateralTokenAdapter.addToWhitelist(DeployerAddress.address);
  });

  describe("Fixed Interface Logic Tests", () => {
    it("✅ should accept native decimals and convert to WAD correctly", async () => {
      console.log("📊 Testing corrected interface logic:");
      
      // Mint 1 token in native 9 decimals (1,000,000,000)
      const tokenAmount = BigNumber.from("1000000000"); // 1 token with 9 decimals
      await token9Decimals.mint(DeployerAddress.address, tokenAmount);
      await token9Decimals.approve(collateralTokenAdapter.address, tokenAmount);
      
      console.log(`   Native amount input: ${tokenAmount.toString()} (9 decimals)`);
      
      // Deposit using native amount (this is the CORRECT way now)
      await collateralTokenAdapter.deposit(DeployerAddress.address, tokenAmount, "0x");
      
      // Check what's stored in BookKeeper (should be WAD)
      const storedWAD = await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), DeployerAddress.address);
      const expectedWAD = tokenAmount.mul(BigNumber.from(10).pow(9)); // Convert 9 decimals to 18 decimals
      
      console.log(`   Expected WAD stored: ${expectedWAD.toString()} (18 decimals)`);
      console.log(`   Actually stored: ${storedWAD.toString()}`);
      
      expect(storedWAD).to.equal(expectedWAD);
      console.log("   ✅ INTERFACE FIXED: Native input → WAD storage works correctly!");
      
      // Test withdrawal
      await collateralTokenAdapter.withdraw(DeployerAddress.address, tokenAmount, "0x");
      const finalStored = await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), DeployerAddress.address);
      const finalBalance = await token9Decimals.balanceOf(DeployerAddress.address);
      
      expect(finalStored).to.equal(0);
      expect(finalBalance).to.equal(tokenAmount);
      console.log("   ✅ Round-trip deposit/withdraw works correctly!");
    });

    it("✅ should handle fractional amounts without precision loss", async () => {
      console.log("📊 Testing precision preservation:");
      
      // Test with 0.1 tokens (100,000,000 in 9 decimals)
      const smallAmount = BigNumber.from("100000000"); // 0.1 tokens with 9 decimals
      await token9Decimals.mint(DeployerAddress.address, smallAmount);
      await token9Decimals.approve(collateralTokenAdapter.address, smallAmount);
      
      console.log(`   Small amount: ${smallAmount.toString()} (0.1 tokens in 9 decimals)`);
      
      await collateralTokenAdapter.deposit(DeployerAddress.address, smallAmount, "0x");
      
      const storedWAD = await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), DeployerAddress.address);
      const expectedWAD = smallAmount.mul(BigNumber.from(10).pow(9));
      
      console.log(`   Stored WAD: ${storedWAD.toString()}`);
      console.log(`   Expected WAD: ${expectedWAD.toString()}`);
      
      expect(storedWAD).to.equal(expectedWAD);
      console.log("   ✅ NO PRECISION LOSS: Small amounts preserved correctly!");
    });

    it("✅ should handle multiple decimal tokens consistently", async () => {
      console.log("📊 Testing multi-decimal consistency:");
      
      // Deploy 6 decimals token (USDC-like)
      const ERC20MintableStableSwapFactory = await ethers.getContractFactory("ERC20MintableStableSwap");
      const token6Decimals = await ERC20MintableStableSwapFactory.deploy("USDC Mock", "USDC");
      await token6Decimals.deployed();

      // Deploy another adapter for 6 decimals
      const CollateralTokenAdapterFactory = await ethers.getContractFactory("CollateralTokenAdapter");
      const adapter6Decimals = await CollateralTokenAdapterFactory.deploy();
      await adapter6Decimals.deployed();

      const MockVaultFactory = await ethers.getContractFactory("MockVault");
      const vault6Decimals = await MockVaultFactory.deploy(
        formatBytes32String("6DECIMALS"),
        token6Decimals.address,
        adapter6Decimals.address
      );
      await vault6Decimals.deployed();

      await adapter6Decimals.initialize(
        bookKeeper.address,
        formatBytes32String("6DECIMALS"),
        token6Decimals.address,
        DeployerAddress.address
      );

      await adapter6Decimals.setVault(vault6Decimals.address);
      await adapter6Decimals.addToWhitelist(DeployerAddress.address);

      // Test 1 token in each format
      const amount9Decimals = BigNumber.from("1000000000"); // 1 token with 9 decimals
      const amount6Decimals = BigNumber.from("1000000"); // 1 token with 6 decimals

      await token9Decimals.mint(DeployerAddress.address, amount9Decimals);
      await token6Decimals.mint(DeployerAddress.address, amount6Decimals);

      await token9Decimals.approve(collateralTokenAdapter.address, amount9Decimals);
      await token6Decimals.approve(adapter6Decimals.address, amount6Decimals);

      await collateralTokenAdapter.deposit(DeployerAddress.address, amount9Decimals, "0x");
      await adapter6Decimals.deposit(DeployerAddress.address, amount6Decimals, "0x");

      const stored9Decimals = await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), DeployerAddress.address);
      const stored6Decimals = await bookKeeper.collateralToken(formatBytes32String("6DECIMALS"), DeployerAddress.address);

      const WAD = BigNumber.from("1000000000000000000"); // 1 WAD
      expect(stored9Decimals).to.equal(WAD);
      expect(stored6Decimals).to.equal(WAD);
      
      console.log("   ✅ CONSISTENCY: Both 6 and 9 decimal tokens store 1 WAD for 1 token!");
    });
  });
}); 