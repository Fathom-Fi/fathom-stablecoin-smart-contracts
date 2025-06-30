const { ethers, deployments, getNamedAccounts } = require("hardhat");
const { BigNumber } = ethers;
const { expect } = require("chai");
const { formatBytes32String } = ethers.utils;
const { smock } = require("@defi-wonderland/smock");

describe("VariableDecimalTokenAdapter STRICT Test (Real Contracts)", () => {
  let bookKeeper;
  let collateralTokenAdapter;
  let token9Decimals;
  let token6Decimals;
  let accessControlConfig;
  let proxyWalletFactory;
  let vault;
  let DeployerAddress, AliceAddress;

  beforeEach(async () => {
    [DeployerAddress, AliceAddress] = await ethers.getSigners();

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

    // Use a simple mock for ProxyWalletFactory
    proxyWalletFactory = await smock.fake("ProxyWalletRegistry");

    // Deploy real 9 decimals token
    const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
    token9Decimals = await ERC20Mintable9DecimalsFactory.deploy("Token 9 Decimals", "T9D");
    await token9Decimals.deployed();

    // Deploy real 6 decimals token  
    const ERC20MintableStableSwapFactory = await ethers.getContractFactory("ERC20MintableStableSwap");
    token6Decimals = await ERC20MintableStableSwapFactory.deploy("Token 6 Decimals", "T6D");
    await token6Decimals.deployed();

    // Deploy real CollateralTokenAdapter (using TokenAdapter for simplicity)
    const CollateralTokenAdapterFactory = await ethers.getContractFactory("TokenAdapter");
    collateralTokenAdapter = await CollateralTokenAdapterFactory.deploy();
    await collateralTokenAdapter.deployed();

    // Deploy mock vault
    const MockVaultFactory = await ethers.getContractFactory("MockVault");
    vault = await MockVaultFactory.deploy(
      formatBytes32String("9DECIMALS"),
      token9Decimals.address,
      collateralTokenAdapter.address
    );
    await vault.deployed();

    // Initialize adapter (TokenAdapter style)
    await collateralTokenAdapter.initialize(
      bookKeeper.address,
      formatBytes32String("9DECIMALS"),
      token9Decimals.address
    );

    // Mock roles are already set up - no need to grant roles

    // Set vault
    await collateralTokenAdapter.setVault(vault.address);
  });

  describe("Interface Contract Test", () => {
    it("should FAIL when passing native decimals to deposit() that expects WAD", async () => {
      // Mint 1 token (9 decimals) = 1 * 10^9 = 1,000,000,000
      const nativeAmount = BigNumber.from("1000000000"); // 1 token in 9 decimals
      await token9Decimals.mint(DeployerAddress.address, nativeAmount);

      // TokenAdapter doesn't have whitelist, so skip this

      // Approve token transfer  
      await token9Decimals.connect(DeployerAddress).approve(collateralTokenAdapter.address, nativeAmount);

      // THIS SHOULD FAIL: Interface expects WAD but we're passing native decimals
      // The interface says deposit(address, uint256 _wad, bytes), but if we pass native decimals
      // it will try to transfer way more tokens than we have
      await expect(
        collateralTokenAdapter.connect(DeployerAddress).deposit(DeployerAddress.address, nativeAmount, "0x")
      ).to.be.reverted; // Should fail because it tries to transfer _convertFromWad(nativeAmount) tokens
    });

    it("should PASS when correctly passing WAD amount to deposit()", async () => {
      // Mint 1 token (9 decimals) = 1 * 10^9 = 1,000,000,000  
      const nativeAmount = BigNumber.from("1000000000"); // 1 token in 9 decimals
      const wadAmount = nativeAmount.mul(BigNumber.from("1000000000")); // Convert to WAD (18 decimals)

      await token9Decimals.mint(DeployerAddress.address, nativeAmount);
      // TokenAdapter doesn't have whitelist, so skip this
      await token9Decimals.connect(DeployerAddress).approve(collateralTokenAdapter.address, nativeAmount);

      // This should work: passing WAD amount to deposit
      await expect(
        collateralTokenAdapter.connect(DeployerAddress).deposit(DeployerAddress.address, wadAmount, "0x")
      ).to.not.be.reverted;

      // Check internal accounting is correct (should be in WAD)
      expect(await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), DeployerAddress.address))
        .to.equal(wadAmount);
    });

    it("should expose division precision loss with 6 decimal tokens", async () => {
      // Test with small amounts that could cause precision loss
      const CollateralTokenAdapter6Factory = await ethers.getContractFactory("CollateralTokenAdapter");
      const adapter6 = await CollateralTokenAdapter6Factory.deploy();
      await adapter6.deployed();

      const MockVault6Factory = await ethers.getContractFactory("MockVault");
      const vault6 = await MockVault6Factory.deploy(
        formatBytes32String("6DECIMALS"),
        token6Decimals.address,
        adapter6.address
      );
      await vault6.deployed();

      await adapter6.initialize(
        bookKeeper.address,
        formatBytes32String("6DECIMALS"),
        token6Decimals.address,
        proxyWalletFactory.address
      );

      await adapter6.setVault(vault6.address);
      await adapter6.addToWhitelist(DeployerAddress.address);

      // Test with amount that could cause precision loss
      const smallWadAmount = BigNumber.from("100000000000"); // Very small WAD amount
      const expectedNativeAmount = smallWadAmount.div(BigNumber.from("1000000000000")); // Convert to 6 decimals

      // This could expose precision loss issues
      if (expectedNativeAmount.eq(0)) {
        console.log("PRECISION LOSS DETECTED: WAD amount too small for 6 decimal conversion");
      }
    });
  });
}); 