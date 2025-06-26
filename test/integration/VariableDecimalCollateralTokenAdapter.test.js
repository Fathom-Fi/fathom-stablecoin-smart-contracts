const { ethers, deployments, getNamedAccounts } = require("hardhat");
const { BigNumber } = ethers;
const { formatBytes32String } = ethers.utils;
const { expect } = require("chai");

const { loadFixturePhase } = require("../helper/test-helpers");

describe("VariableDecimalCollateralTokenAdapter Integration", () => {
  let bookKeeper;
  let accessControlConfig;
  let vault;
  let collateralTokenAdapter;
  let proxyWalletFactory;
  let proxyFactory;
  let simplePriceFeed;
  let collateralPoolConfig;
  let priceOracle;
  let fixedSpreadLiquidationStrategy;
  let token9Decimals, token6Decimals;
  
  let DeployerAddress, AliceAddress, BobAddress;

  before(async () => {
    await deployments.fixture(["DeployTestFixture"]);
    ({ DeployerAddress, AliceAddress, BobAddress } = await getNamedAccounts());

    proxyFactory = await ethers.getContract("FathomProxyFactory");
    bookKeeper = await ethers.getContractAt("BookKeeper", await proxyFactory.lookup("BookKeeper"));
    accessControlConfig = await ethers.getContractAt("AccessControlConfig", await proxyFactory.lookup("AccessControlConfig"));
    collateralPoolConfig = await ethers.getContractAt("CollateralPoolConfig", await proxyFactory.lookup("CollateralPoolConfig"));
    priceOracle = await ethers.getContractAt("PriceOracle", await proxyFactory.lookup("PriceOracle"));
    simplePriceFeed = await ethers.getContract("SimplePriceFeed");
    fixedSpreadLiquidationStrategy = await ethers.getContractAt("FixedSpreadLiquidationStrategy", await proxyFactory.lookup("FixedSpreadLiquidationStrategy"));
    proxyWalletFactory = await ethers.getContractAt("ProxyWalletFactory", await proxyFactory.lookup("ProxyWalletFactory"));

    // Deploy 9 decimals token
    const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
    token9Decimals = await ERC20Mintable9DecimalsFactory.deploy("Token 9 Decimals", "T9D");
    await token9Decimals.deployed();

    // Deploy 6 decimals token (like USDC)
    const ERC20MintableStableSwapFactory = await ethers.getContractFactory("ERC20MintableStableSwap");
    token6Decimals = await ERC20MintableStableSwapFactory.deploy("Token 6 Decimals", "T6D");
    await token6Decimals.deployed();

    // Deploy new CollateralTokenAdapter for 9 decimals token
    const CollateralTokenAdapterFactory = await ethers.getContractFactory("CollateralTokenAdapter");
    collateralTokenAdapter = await CollateralTokenAdapterFactory.deploy();
    await collateralTokenAdapter.deployed();

    // Deploy vault for 9 decimals token
    const MockVaultFactory = await ethers.getContractFactory("MockVault");
    vault = await MockVaultFactory.deploy(
      formatBytes32String("9DECIMALS"),
      token9Decimals.address,
      collateralTokenAdapter.address
    );
    await vault.deployed();
  });

  describe("9 Decimals Token Integration", () => {
    beforeEach(async () => {
      await collateralTokenAdapter.initialize(
        bookKeeper.address,
        formatBytes32String("9DECIMALS"),
        token9Decimals.address,
        proxyWalletFactory.address
      );

      await collateralTokenAdapter.setVault(vault.address);
    });

    describe("#decimals()", () => {
      it("should return 9 for the 9-decimal token", async () => {
        expect(await collateralTokenAdapter.decimals()).to.equal(9);
      });
    });

    describe("Pool initialization with 9 decimals token", () => {
      it("should initialize collateral pool with 9 decimals token", async () => {
        const WeiPerWad = BigNumber.from(`1${"0".repeat(18)}`);
        const WeiPerRay = BigNumber.from(`1${"0".repeat(27)}`);
        const WeiPerRad = BigNumber.from(`1${"0".repeat(45)}`);

        // Set up price feed
        await simplePriceFeed.setPoolId(formatBytes32String("9DECIMALS"));
        await simplePriceFeed.setPrice(WeiPerWad.toString()); // 1 USD

        await collateralPoolConfig.initCollateralPool(
          formatBytes32String("9DECIMALS"),
          WeiPerRad.mul(10000000).div(2), // debtCeiling
          WeiPerRad.mul(0), // debtFloor
          WeiPerRad.mul(50000), // positionDebtCeiling
          simplePriceFeed.address,
          WeiPerRay.mul(133).div(100), // liquidationRatio (75% LTV)
          BigNumber.from("1000000000627937192491029811"), // stabilityFeeRate
          collateralTokenAdapter.address,
          BigNumber.from(2500), // closeFactorBps
          BigNumber.from(10500), // liquidatorIncentiveBps
          BigNumber.from(8000), // treasuryFeesBps
          fixedSpreadLiquidationStrategy.address
        );

        await priceOracle.setPrice(formatBytes32String("9DECIMALS"));
        
        expect(await collateralPoolConfig.getAdapter(formatBytes32String("9DECIMALS"))).to.equal(collateralTokenAdapter.address);
      });
    });

    describe("Deposit and withdrawal with 9 decimals", () => {
      beforeEach(async () => {
        const WeiPerWad = BigNumber.from(`1${"0".repeat(18)}`);
        const WeiPerRay = BigNumber.from(`1${"0".repeat(27)}`);
        const WeiPerRad = BigNumber.from(`1${"0".repeat(45)}`);

        await simplePriceFeed.setPoolId(formatBytes32String("9DECIMALS"));
        await simplePriceFeed.setPrice(WeiPerWad.toString());

        await collateralPoolConfig.initCollateralPool(
          formatBytes32String("9DECIMALS"),
          WeiPerRad.mul(10000000).div(2),
          WeiPerRad.mul(0),
          WeiPerRad.mul(50000),
          simplePriceFeed.address,
          WeiPerRay.mul(133).div(100),
          BigNumber.from("1000000000627937192491029811"),
          collateralTokenAdapter.address,
          BigNumber.from(2500),
          BigNumber.from(10500),
          BigNumber.from(8000),
          fixedSpreadLiquidationStrategy.address
        );

        await priceOracle.setPrice(formatBytes32String("9DECIMALS"));
      });

      it("should handle deposits and withdrawals correctly", async () => {
        // Mint tokens to Alice (1 token = 10^9 wei in 9 decimals)
        const tokenAmount = BigNumber.from("1000000000"); // 1 token with 9 decimals
        await token9Decimals.mint(AliceAddress, tokenAmount);
        
        // Alice needs to be whitelisted
        await collateralTokenAdapter.addToWhitelist(AliceAddress);
        
        // Approve and deposit
        await token9Decimals.connect(ethers.provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, tokenAmount);
        
        await collateralTokenAdapter
          .connect(ethers.provider.getSigner(AliceAddress))
          .deposit(AliceAddress, tokenAmount, ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        // Check internal bookkeeping (should be in WAD - 18 decimals)
        expect(await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), AliceAddress)).to.equal(tokenAmount);
        expect(await collateralTokenAdapter.totalShare()).to.equal(tokenAmount);

        // Withdraw
        await collateralTokenAdapter
          .connect(ethers.provider.getSigner(AliceAddress))
          .withdraw(AliceAddress, tokenAmount, ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), AliceAddress)).to.equal(0);
        expect(await collateralTokenAdapter.totalShare()).to.equal(0);
        expect(await token9Decimals.balanceOf(AliceAddress)).to.equal(tokenAmount);
      });

      it("should handle fractional amounts correctly", async () => {
        // Test with 0.5 tokens (5 * 10^8 in 9 decimals)
        const fractionalAmount = BigNumber.from("500000000"); // 0.5 tokens with 9 decimals
        await token9Decimals.mint(AliceAddress, fractionalAmount);
        
        await collateralTokenAdapter.addToWhitelist(AliceAddress);
        await token9Decimals.connect(ethers.provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, fractionalAmount);
        
        await collateralTokenAdapter
          .connect(ethers.provider.getSigner(AliceAddress))
          .deposit(AliceAddress, fractionalAmount, ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), AliceAddress)).to.equal(fractionalAmount);
      });
    });

    describe("Multiple users with different amounts", () => {
      beforeEach(async () => {
        const WeiPerWad = BigNumber.from(`1${"0".repeat(18)}`);
        const WeiPerRay = BigNumber.from(`1${"0".repeat(27)}`);
        const WeiPerRad = BigNumber.from(`1${"0".repeat(45)}`);

        await simplePriceFeed.setPoolId(formatBytes32String("9DECIMALS"));
        await simplePriceFeed.setPrice(WeiPerWad.toString());

        await collateralPoolConfig.initCollateralPool(
          formatBytes32String("9DECIMALS"),
          WeiPerRad.mul(10000000).div(2),
          WeiPerRad.mul(0),
          WeiPerRad.mul(50000),
          simplePriceFeed.address,
          WeiPerRay.mul(133).div(100),
          BigNumber.from("1000000000627937192491029811"),
          collateralTokenAdapter.address,
          BigNumber.from(2500),
          BigNumber.from(10500),
          BigNumber.from(8000),
          fixedSpreadLiquidationStrategy.address
        );

        await priceOracle.setPrice(formatBytes32String("9DECIMALS"));
        await collateralTokenAdapter.addToWhitelist(AliceAddress);
        await collateralTokenAdapter.addToWhitelist(BobAddress);
      });

      it("should track multiple users' balances correctly", async () => {
        // Alice deposits 2.5 tokens
        const aliceAmount = BigNumber.from("2500000000"); // 2.5 tokens
        await token9Decimals.mint(AliceAddress, aliceAmount);
        await token9Decimals.connect(ethers.provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, aliceAmount);
        await collateralTokenAdapter
          .connect(ethers.provider.getSigner(AliceAddress))
          .deposit(AliceAddress, aliceAmount, ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        // Bob deposits 1.25 tokens
        const bobAmount = BigNumber.from("1250000000"); // 1.25 tokens
        await token9Decimals.mint(BobAddress, bobAmount);
        await token9Decimals.connect(ethers.provider.getSigner(BobAddress)).approve(collateralTokenAdapter.address, bobAmount);
        await collateralTokenAdapter
          .connect(ethers.provider.getSigner(BobAddress))
          .deposit(BobAddress, bobAmount, ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

        // Check individual balances
        expect(await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), AliceAddress)).to.equal(aliceAmount);
        expect(await bookKeeper.collateralToken(formatBytes32String("9DECIMALS"), BobAddress)).to.equal(bobAmount);
        
        // Check total
        expect(await collateralTokenAdapter.totalShare()).to.equal(aliceAmount.add(bobAmount));
      });
    });
  });

  describe("6 Decimals Token Integration (USDC-like)", () => {
    let collateralTokenAdapter6;
    let vault6;

    beforeEach(async () => {
      // Deploy new adapter for 6 decimals token
      const CollateralTokenAdapterFactory = await ethers.getContractFactory("CollateralTokenAdapter");
      collateralTokenAdapter6 = await CollateralTokenAdapterFactory.deploy();
      await collateralTokenAdapter6.deployed();

      // Deploy vault for 6 decimals token
      const MockVaultFactory = await ethers.getContractFactory("MockVault");
      vault6 = await MockVaultFactory.deploy(
        formatBytes32String("6DECIMALS"),
        token6Decimals.address,
        collateralTokenAdapter6.address
      );
      await vault6.deployed();

      await collateralTokenAdapter6.initialize(
        bookKeeper.address,
        formatBytes32String("6DECIMALS"),
        token6Decimals.address,
        proxyWalletFactory.address
      );

      await collateralTokenAdapter6.setVault(vault6.address);
    });

    it("should handle 6 decimals token correctly", async () => {
      expect(await collateralTokenAdapter6.decimals()).to.equal(6);
      
      // Test with 100 USDC (100 * 10^6)
      const usdcAmount = BigNumber.from("100000000"); // 100 USDC with 6 decimals
      await token6Decimals.mint(AliceAddress, usdcAmount);
      
      await collateralTokenAdapter6.addToWhitelist(AliceAddress);
      await token6Decimals.connect(ethers.provider.getSigner(AliceAddress)).approve(collateralTokenAdapter6.address, usdcAmount);
      
      await collateralTokenAdapter6
        .connect(ethers.provider.getSigner(AliceAddress))
        .deposit(AliceAddress, usdcAmount, ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

      expect(await bookKeeper.collateralToken(formatBytes32String("6DECIMALS"), AliceAddress)).to.equal(usdcAmount);
    });
  });
}); 