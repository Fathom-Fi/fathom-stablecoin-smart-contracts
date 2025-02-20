const fs = require("fs");
const { ethers } = require("hardhat");

const pools = require("../../../common/collateral");
const { getAddresses } = require("../../../common/addresses");
const { getProxy } = require("../../../common/proxies");

async function initialize(deployments, getChainId, forFixture = false) {
  const { log } = deployments;
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
  // To be sunsetted on xdc mainnet, then to be deprecated
  // const stableSwapModule = await getProxy(proxyFactory, "StableSwapModule");
  // const flashMintArbitrager = await getProxy(proxyFactory, "FlashMintArbitrager");
  // const bookKeeperFlashMintArbitrager = await getProxy(proxyFactory, "BookKeeperFlashMintArbitrager");
  // const delayFathomOraclePriceFeed = await getProxy(proxyFactory, "DelayFathomOraclePriceFeed");
  // const dexPriceOracle = await getProxy(proxyFactory, "DexPriceOracle");
  const collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
  const proxyActionsStorage = await getProxy(proxyFactory, "ProxyActionsStorage");
  const adminControls = await getProxy(proxyFactory, "AdminControls");
  const centralizedOraclePriceFeed = await getProxy(proxyFactory, "CentralizedOraclePriceFeed");
  const fathomPriceOracle = await getProxy(proxyFactory, "FathomPriceOracle");
  // To be sunsetted on xdc mainnet, then to be deprecated
  // const stableSwapModuleWrapper = await getProxy(proxyFactory, "StableSwapModuleWrapper");
  const simplePriceFeed = await getProxy(proxyFactory, "SimplePriceFeed");
  // const slidingWindowDexOracle = await getProxy(proxyFactory, "SlidingWindowDexOracle");

  const fathomStablecoinProxyActions = await ethers.getContractAt("FathomStablecoinProxyActions", FathomStablecoinProxyActions.address);

  const addresses = getAddresses(chainId);

  await accessControlConfig.initialize();
  console.log("AccessControlConfig initialized");
  await collateralPoolConfig.initialize(accessControlConfig.address);
  console.log("CollateralPoolConfig initialized");
  await bookKeeper.initialize(collateralPoolConfig.address, accessControlConfig.address);
  console.log("BookKeeper initialized");
  await fathomStablecoin.initialize("Fathom USD", "FXD");
  console.log("FathomStablecoin initialized");
  await systemDebtEngine.initialize(bookKeeper.address);
  console.log("SystemDebtEngine initialized");
  await liquidationEngine.initialize(bookKeeper.address, systemDebtEngine.address);
  console.log("LiquidationEngine initialized");
  await stablecoinAdapter.initialize(bookKeeper.address, fathomStablecoin.address);
  console.log("StablecoinAdapter initialized");
  await priceOracle.initialize(bookKeeper.address);
  console.log("PriceOracle initialized");
  await showStopper.initialize(bookKeeper.address);
  console.log("ShowStopper initialized");
  await positionManager.initialize(bookKeeper.address, showStopper.address, priceOracle.address);
  console.log("PositionManager initialized");
  await fixedSpreadLiquidationStrategy.initialize(
    bookKeeper.address,
    priceOracle.address,
    liquidationEngine.address,
    systemDebtEngine.address,
    stablecoinAdapter.address
  );
  console.log("FixedSpreadLiquidationStrategy initialized");
  await stabilityFeeCollector.initialize(bookKeeper.address, systemDebtEngine.address);
  console.log("StabilityFeeCollector initialized");
  await proxyActionsStorage.initialize(fathomStablecoinProxyActions.address, bookKeeper.address);
  console.log("ProxyActionsStorage initialized");
  await proxyWalletFactory.initialize(proxyActionsStorage.address, proxyWalletRegistry.address);
  console.log("ProxyWalletFactory initialized");
  await proxyWalletRegistry.initialize(proxyWalletFactory.address, bookKeeper.address);
  console.log("ProxyWalletRegistry initialized");
  await proxyWalletRegistry.setDecentralizedMode(true);
  console.log("ProxyWalletRegistry setDecentralizedMode");
  await flashMintModule.initialize(stablecoinAdapter.address, systemDebtEngine.address);
  console.log("FlashMintModule initialized");
  // To be sunsetted on xdc mainnet, then to be deprecated
  // await stableSwapModule.initialize(
  //     bookKeeper.address,
  //     addresses.USDSTABLE,
  //     fathomStablecoin.address,
  //     dailyLimitNumerator,
  //     singleSwapLimitNumerator,
  //     numberOfSwapsLimitPerUser,
  //     blocksPerLimit,
  //     { gasLimit: 1000000 }
  // ),
  // await flashMintArbitrager.initialize({ gasLimit: 1000000 }),
  // await bookKeeperFlashMintArbitrager.initialize(fathomStablecoin.address, { gasLimit: 1000000 }),
  // await dexPriceOracle.initialize(addresses.DEXFactory, { gasLimit: 1000000 }),
  let wnativeAddress;
  if (forFixture) {
    const WNATIVE = await deployments.get("WNATIVE");
    wnativeAddress = WNATIVE.address;
  } else {
    wnativeAddress = addresses.WNATIVE;
  }
  await collateralTokenAdapter.initialize(bookKeeper.address, pools.NATIVE, wnativeAddress, proxyWalletFactory.address);
  console.log("CollateralTokenAdapter initialized");
  // await delayFathomOraclePriceFeed.initialize(
  //     dexPriceOracle.address,
  //     addresses.WNATIVE,
  //     addresses.USD,
  //     accessControlConfig.address,
  //     pools.NATIVE
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
  console.log("AdminControls initialized");
  await centralizedOraclePriceFeed.initialize(fathomPriceOracle.address, accessControlConfig.address, pools.NATIVE);
  console.log("CentralizedOraclePriceFeed initialized");
  // FathomPriceOracle is not initialized in this script because it needs to be initialized only when the NATIVE coin's price aggregator is ready
  // await fathomPriceOracle.initialize(accessControlConfig.address, NATIVECOIN_s_AGGREGATOR),
  // To be sunsetted on xdc mainnet, then to be deprecated
  // await stableSwapModuleWrapper.initialize(
  //     bookKeeper.address,
  //     stableSwapModule.address),
  await simplePriceFeed.initialize(accessControlConfig.address);
  console.log("SimplePriceFeed initialized");
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
    // To be sunsetted on xdc mainnet, then to be deprecated
    // stableSwapModule: stableSwapModule.address,
    // No longer needed in deployments
    // flashMintArbitrager: flashMintArbitrager.address,
    // bookKeeperFlashMintArbitrager: bookKeeperFlashMintArbitrager.address,
    // dexPriceOracle: dexPriceOracle.address,
    proxyWalletFactory: proxyWalletFactory.address,
    fathomStablecoinProxyActions: FathomStablecoinProxyActions.address,
    collateralTokenAdapter: collateralTokenAdapter.address,
    // delayFathomOraclePriceFeed: delayFathomOraclePriceFeed.address,
    adminControls: adminControls.address,
    centralizedOraclePriceFeed: centralizedOraclePriceFeed.address,
    fathomPriceOracle: fathomPriceOracle.address,
    proxyActionsStorage: proxyActionsStorage.address,
    fathomProxyAdmin: proxyAdmin.address,
    // slidingWindowDexOracle: slidingWindowDexOracle.address,
  };

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Initializing Proxies Finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");

  fs.writeFileSync("./addresses.json", JSON.stringify(newAddresses));
}

module.exports = {
  initialize,
};
