const { ethers } = require("hardhat");
const { formatBytes32String } = ethers.utils;

const contracts = [
  "AccessControlConfig",
  "CollateralPoolConfig",
  "BookKeeper",
  "FathomStablecoin",
  "SystemDebtEngine",
  "LiquidationEngine",
  "StablecoinAdapter",
  "PriceOracle",
  "ShowStopper",
  "PositionManager",
  "FixedSpreadLiquidationStrategy",
  "StabilityFeeCollector",
  "ProxyWalletRegistry",
  "ProxyWalletFactory",
  "ProxyActionsStorage",
  "FlashMintModule",
  // To be sunsetted on xdc mainnet, then to be deprecated
  // "StableSwapModule",
  // "FlashMintArbitrager",
  // "BookKeeperFlashMintArbitrager",
  // "DelayFathomOraclePriceFeed",
  // "DexPriceOracle",
  "CollateralTokenAdapter",
  // "SlidingWindowDexOracle",
  "AdminControls",
  "CentralizedOraclePriceFeed",
  "FathomPriceOracle",
  // To be sunsetted on xdc mainnet, then to be deprecated
  // "StableSwapModuleWrapper",
  "SimplePriceFeed",
];

async function deployProxies(deployments) {
  const { log } = deployments;

  const fathomProxyFactory = await deployments.get("FathomProxyFactory");
  const fathomProxyFactoryAddress = fathomProxyFactory.address;

  const fathomProxyAdmin = await deployments.get("FathomProxyAdmin");
  const fathomProxyAdminAddress = fathomProxyAdmin.address;

  const fathomProxyFactoryContract = await ethers.getContractAt("FathomProxyFactory", fathomProxyFactoryAddress);

  for (let i = 0; i < contracts.length; i++) {
    const contract = contracts[i];
    const instance = await deployments.get(contract);
    await fathomProxyFactoryContract.createProxy(formatBytes32String(contract), instance.address, fathomProxyAdminAddress, "0x");
    log(`${contract} Proxy created`);
  }

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Deploying Proxies Finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  deployProxies,
};
