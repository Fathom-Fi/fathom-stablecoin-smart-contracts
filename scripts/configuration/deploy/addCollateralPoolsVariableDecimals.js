const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const { getProxy } = require("../../../common/proxies");
const { getConfigInitialCollateral } = require("../../../common/collateral-setup-helper");

const WeiPerWad = BigNumber.from(`1${"0".repeat(18)}`);
const WeiPerRay = BigNumber.from(`1${"0".repeat(27)}`);
const WeiPerRad = BigNumber.from(`1${"0".repeat(45)}`);

async function addCollateralPoolsVariableDecimals(deployments, getChainId) {
  const { log } = deployments;
  const chainId = await getChainId();

  const config = getConfigInitialCollateral(chainId);
  const CLOSE_FACTOR_BPS = BigNumber.from(config.CLOSE_FACTOR_BPS);
  const LIQUIDATOR_INCENTIVE_BPS = BigNumber.from(config.LIQUIDATOR_INCENTIVE_BPS);
  const TREASURY_FEE_BPS = BigNumber.from(config.TREASURY_FEE_BPS);
  const STABILITY_FEE = BigNumber.from(config.STABILITY_FEE);
  const LIQUIDATIONRATIO = WeiPerRay.mul(config.LIQUIDATIONRATIO_NUMERATOR).div(config.LIQUIDATIONRATIO_DENOMINATOR).toString();
  const debtCeilingSetUpTotal = WeiPerRad.mul(config.DEBTCELINGSETUP_TOTAL);
  const debtCeilingSetUp = WeiPerRad.mul(config.DEBTCELINGSETUP_NUMERATOR).div(config.DEBTCELINGSETUP_DENOMINATOR);
  const debtFloor = WeiPerRad.mul(config.DEBT_FLOOR);
  const positionDebtCeiling = WeiPerRad.mul(config.POSITION_DEBT_CEILING);

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);
  
  const fixedSpreadLiquidationStrategy = await getProxy(proxyFactory, "FixedSpreadLiquidationStrategy");
  const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
  const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");
  const priceOracle = await getProxy(proxyFactory, "PriceOracle");

  // Deploy test tokens with different decimals
  const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
  const token9Decimals = await ERC20Mintable9DecimalsFactory.deploy("Token 9 Decimals", "T9D");
  await token9Decimals.deployed();
  log(`Deployed 9 decimal token at: ${token9Decimals.address}`);

  const ERC20MintableStableSwapFactory = await ethers.getContractFactory("ERC20MintableStableSwap");
  const token6Decimals = await ERC20MintableStableSwapFactory.deploy("Token 6 Decimals", "T6D");
  await token6Decimals.deployed();
  log(`Deployed 6 decimal token (USDC-like) at: ${token6Decimals.address}`);

  // Deploy CollateralTokenAdapters for different decimal tokens
  const CollateralTokenAdapterFactory = await ethers.getContractFactory("CollateralTokenAdapter");
  
  const adapter9Decimals = await CollateralTokenAdapterFactory.deploy();
  await adapter9Decimals.deployed();
  log(`Deployed 9 decimal adapter at: ${adapter9Decimals.address}`);

  const adapter6Decimals = await CollateralTokenAdapterFactory.deploy();
  await adapter6Decimals.deployed();
  log(`Deployed 6 decimal adapter at: ${adapter6Decimals.address}`);

  // Initialize adapters
  const proxyWalletFactory = await getProxy(proxyFactory, "ProxyWalletFactory");
  
  await adapter9Decimals.initialize(
    bookKeeper.address,
    ethers.utils.formatBytes32String("T9D"),
    token9Decimals.address,
    proxyWalletFactory.address
  );
  log(`Initialized 9 decimal adapter with ${await adapter9Decimals.decimals()} decimals`);

  await adapter6Decimals.initialize(
    bookKeeper.address,
    ethers.utils.formatBytes32String("T6D"),
    token6Decimals.address,
    proxyWalletFactory.address
  );
  log(`Initialized 6 decimal adapter with ${await adapter6Decimals.decimals()} decimals`);

  // Deploy SimplePriceFeeds for each token
  const SimplePriceFeedFactory = await ethers.getContractFactory("SimplePriceFeed");
  
  const priceFeed9Decimals = await SimplePriceFeedFactory.deploy();
  await priceFeed9Decimals.deployed();
  await priceFeed9Decimals.initialize(await getProxy(proxyFactory, "AccessControlConfig").then(c => c.address));
  await priceFeed9Decimals.setPrice(WeiPerWad.toString()); // 1 USD
  await priceFeed9Decimals.setPoolId(ethers.utils.formatBytes32String("T9D"));
  
  const priceFeed6Decimals = await SimplePriceFeedFactory.deploy();
  await priceFeed6Decimals.deployed();
  await priceFeed6Decimals.initialize(await getProxy(proxyFactory, "AccessControlConfig").then(c => c.address));
  await priceFeed6Decimals.setPrice(WeiPerWad.toString()); // 1 USD
  await priceFeed6Decimals.setPoolId(ethers.utils.formatBytes32String("T6D"));

  // Deploy Vaults
  const MockVaultFactory = await ethers.getContractFactory("MockVault");
  
  const vault9Decimals = await MockVaultFactory.deploy(
    ethers.utils.formatBytes32String("T9D"),
    token9Decimals.address,
    adapter9Decimals.address
  );
  await vault9Decimals.deployed();

  const vault6Decimals = await MockVaultFactory.deploy(
    ethers.utils.formatBytes32String("T6D"),
    token6Decimals.address,
    adapter6Decimals.address
  );
  await vault6Decimals.deployed();

  // Set vaults
  await adapter9Decimals.setVault(vault9Decimals.address);
  await adapter6Decimals.setVault(vault6Decimals.address);

  // Initialize collateral pools
  await initPool(
    ethers.utils.formatBytes32String("T9D"),
    adapter9Decimals.address,
    priceFeed9Decimals.address,
    LIQUIDATIONRATIO,
    "9 decimal token pool"
  );

  await initPool(
    ethers.utils.formatBytes32String("T6D"),
    adapter6Decimals.address,
    priceFeed6Decimals.address,
    LIQUIDATIONRATIO,
    "6 decimal token pool (USDC-like)"
  );

  // Update total debt ceiling to accommodate new pools
  const currentTotalDebtCeiling = await bookKeeper.totalDebtCeiling();
  await bookKeeper.setTotalDebtCeiling(currentTotalDebtCeiling.add(debtCeilingSetUp.mul(2)));

  async function initPool(poolId, adapter, priceFeed, liquidationRatio, description) {
    log(`Initializing ${description}...`);
    
    await collateralPoolConfig.initCollateralPool(
      poolId,
      debtCeilingSetUp,
      debtFloor,
      positionDebtCeiling,
      priceFeed,
      liquidationRatio,
      STABILITY_FEE,
      adapter,
      CLOSE_FACTOR_BPS,
      LIQUIDATOR_INCENTIVE_BPS,
      TREASURY_FEE_BPS,
      fixedSpreadLiquidationStrategy.address
    );

    await priceOracle.setPrice(poolId);
    log(`Successfully initialized ${description}`);
  }

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Variable Decimal Collateral Pools Successfully Initialized!");
  log(`9 Decimal Token: ${token9Decimals.address}`);
  log(`6 Decimal Token: ${token6Decimals.address}`);
  log(`9 Decimal Adapter: ${adapter9Decimals.address}`);
  log(`6 Decimal Adapter: ${adapter6Decimals.address}`);
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  addCollateralPoolsVariableDecimals,
};

module.exports.tags = ["VariableDecimals"];
module.exports.dependencies = ["DeployTestFixture"]; 