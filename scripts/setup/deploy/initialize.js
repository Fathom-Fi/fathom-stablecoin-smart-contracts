const fs = require("fs");
const { ethers } = require("hardhat");

const pools = require("../../../common/collateral");
const { getAddresses } = require("../../../common/addresses");
const { getProxy } = require("../../../common/proxies");

async function initialize(deployments, getChainId, forFixture = false) {
  const chainId = await getChainId();

  const FathomStablecoinProxyActions = await deployments.get("FathomStablecoinProxyActions");

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);
  const ProxyAdmin = await deployments.get("FathomProxyAdmin");
  const proxyAdmin = await ethers.getContractAt("FathomProxyAdmin", ProxyAdmin.address);

  const fixedSpreadLiquidationStrategy = await getProxy(proxyFactory, "FixedSpreadLiquidationStrategy");
  const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");
  const proxyWalletFactory = await getProxy(proxyFactory, "ProxyWalletFactory");
  const stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
  const stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
  const showStopper = await getProxy(proxyFactory, "ShowStopper");
  const priceOracle = await getProxy(proxyFactory, "PriceOracle");
  const fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
  const positionManager = await getProxy(proxyFactory, "PositionManager");
  const systemDebtEngine = await getProxy(proxyFactory, "SystemDebtEngine");
  const liquidationEngine = await getProxy(proxyFactory, "LiquidationEngine");
  const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
  const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");
  const accessControlConfig = await getProxy(proxyFactory, "AccessControlConfig");
  const flashMintModule = await getProxy(proxyFactory, "FlashMintModule");
  const stableSwapModule = await getProxy(proxyFactory, "StableSwapModule");
  const flashMintArbitrager = await getProxy(proxyFactory, "FlashMintArbitrager");
  const bookKeeperFlashMintArbitrager = await getProxy(proxyFactory, "BookKeeperFlashMintArbitrager");
  const delayFathomOraclePriceFeed = await getProxy(proxyFactory, "DelayFathomOraclePriceFeed");
  const dexPriceOracle = await getProxy(proxyFactory, "DexPriceOracle");
  const collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
  const proxyActionsStorage = await getProxy(proxyFactory, "ProxyActionsStorage");
  const adminControls = await getProxy(proxyFactory, "AdminControls");
  const centralizedOraclePriceFeed = await getProxy(proxyFactory, "CentralizedOraclePriceFeed");
  const stableSwapModuleWrapper = await getProxy(proxyFactory, "StableSwapModuleWrapper");
  const simplePriceFeed = await getProxy(proxyFactory, "SimplePriceFeed");
  const slidingWindowDexOracle = await getProxy(proxyFactory, "SlidingWindowDexOracle");

  const fathomStablecoinProxyActions = await ethers.getContractAt("FathomStablecoinProxyActions", FathomStablecoinProxyActions.address);

  const addresses = getAddresses(chainId);
  const dailyLimitNumerator = 2000; //on denomination of 10000th, 2000/10000 = 20%
  const singleSwapLimitNumerator = 100; ///on denomination of 10000th, 100/10000 = 1%
  const numberOfSwapsLimitPerUser = 1; // number of swaps per user per limit period
  const blocksPerLimit = 2; // blocks per limit period

  await accessControlConfig.initialize();
  await collateralPoolConfig.initialize(accessControlConfig.address);
  await bookKeeper.initialize(collateralPoolConfig.address, accessControlConfig.address);
  await fathomStablecoin.initialize("Fathom USD", "FXD");
  await systemDebtEngine.initialize(bookKeeper.address);
  await liquidationEngine.initialize(bookKeeper.address, systemDebtEngine.address);
  await stablecoinAdapter.initialize(bookKeeper.address, fathomStablecoin.address);
  await priceOracle.initialize(bookKeeper.address);
  await showStopper.initialize(bookKeeper.address);
  await positionManager.initialize(bookKeeper.address, showStopper.address, priceOracle.address);
  await fixedSpreadLiquidationStrategy.initialize(
    bookKeeper.address,
    priceOracle.address,
    liquidationEngine.address,
    systemDebtEngine.address,
    stablecoinAdapter.address
  );
  await stabilityFeeCollector.initialize(bookKeeper.address, systemDebtEngine.address);
  await proxyActionsStorage.initialize(fathomStablecoinProxyActions.address, bookKeeper.address);
  await proxyWalletFactory.initialize(proxyActionsStorage.address, proxyWalletRegistry.address);
  await proxyWalletRegistry.initialize(proxyWalletFactory.address, bookKeeper.address);
  await flashMintModule.initialize(stablecoinAdapter.address, systemDebtEngine.address);

  await flashMintModule.setDecentralizedStatesStatus(true);

  await stableSwapModule.initialize(
    bookKeeper.address,
    addresses.USDSTABLE,
    fathomStablecoin.address,
    dailyLimitNumerator,
    singleSwapLimitNumerator,
    numberOfSwapsLimitPerUser,
    blocksPerLimit
  );
  await flashMintArbitrager.initialize();
  await bookKeeperFlashMintArbitrager.initialize(fathomStablecoin.address);
  // await dexPriceOracle.initialize(addresses.DEXFactory, { gasLimit: 1000000 }),

  let wxdcAddress;
  if (forFixture) {
    const WXDC = await deployments.get("WXDC");
    wxdcAddress = WXDC.address;
  } else {
    wxdcAddress = addresses.WXDC;
  }
  await collateralTokenAdapter.initialize(bookKeeper.address, pools.XDC, wxdcAddress, proxyWalletFactory.address);
  // await delayFathomOraclePriceFeed.initialize(
  //     dexPriceOracle.address,
  //     addresses.WXDC,
  //     addresses.USD,
  //     accessControlConfig.address,
  //     pools.XDC
  // ),
  await adminControls.initialize(
    bookKeeper.address,
    liquidationEngine.address,
    priceOracle.address,
    positionManager.address,
    systemDebtEngine.address,
    flashMintModule.address,
    stablecoinAdapter.address
  );
  // await centralizedOraclePriceFeed.initialize(fathomPriceOracle.address, accessControlConfig.address, pools.XDC);
  await stableSwapModuleWrapper.initialize(bookKeeper.address, stableSwapModule.address);
  await simplePriceFeed.initialize(accessControlConfig.address);
  // await slidingWindowDexOracle.initialize(addresses.DEXFactory, 1800, 15);

  const newAddresses = {
    proxyFactory: proxyFactory.address,
    proxyAdmin: proxyAdmin.address,
    fixedSpreadLiquidationStrategy: fixedSpreadLiquidationStrategy.address,
    proxyWalletRegistry: proxyWalletRegistry.address,
    stabilityFeeCollector: stabilityFeeCollector.address,
    stablecoinAdapter: stablecoinAdapter.address,
    showStopper: showStopper.address,
    priceOracle: priceOracle.address,
    fathomStablecoin: fathomStablecoin.address,
    positionManager: positionManager.address,
    systemDebtEngine: systemDebtEngine.address,
    liquidationEngine: liquidationEngine.address,
    bookKeeper: bookKeeper.address,
    collateralPoolConfig: collateralPoolConfig.address,
    accessControlConfig: accessControlConfig.address,
    flashMintModule: flashMintModule.address,
    stableSwapModule: stableSwapModule.address,
    flashMintArbitrager: flashMintArbitrager.address,
    bookKeeperFlashMintArbitrager: bookKeeperFlashMintArbitrager.address,
    dexPriceOracle: dexPriceOracle.address,
    proxyWalletFactory: proxyWalletFactory.address,
    fathomStablecoinProxyActions: FathomStablecoinProxyActions.address,
    collateralTokenAdapter: collateralTokenAdapter.address,
    delayFathomOraclePriceFeed: delayFathomOraclePriceFeed.address,
    adminControls: adminControls.address,
    centralizedOraclePriceFeed: centralizedOraclePriceFeed.address,
    proxyActionsStorage: proxyActionsStorage.address,
    fathomProxyAdmin: proxyAdmin.address,
    slidingWindowDexOracle: slidingWindowDexOracle.address,
  };

  fs.writeFileSync("./addresses.json", JSON.stringify(newAddresses));
}

module.exports = {
  initialize,
};
