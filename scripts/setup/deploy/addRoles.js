const { ethers } = require("hardhat");
const { getProxy } = require("../../../common/proxies");

async function addRoles(deployments) {
  const { log } = deployments;

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

  const fixedSpreadLiquidationStrategy = await getProxy(proxyFactory, "FixedSpreadLiquidationStrategy");
  const stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
  const stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
  const showStopper = await getProxy(proxyFactory, "ShowStopper");
  const priceOracle = await getProxy(proxyFactory, "PriceOracle");
  const fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
  const positionManager = await getProxy(proxyFactory, "PositionManager");
  const liquidationEngine = await getProxy(proxyFactory, "LiquidationEngine");
  const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
  const accessControlConfig = await getProxy(proxyFactory, "AccessControlConfig");
  const flashMintModule = await getProxy(proxyFactory, "FlashMintModule");
  // To be sunsetted on xdc mainnet, then to be deprecated
  // const stableSwapModule = await getProxy(proxyFactory, "StableSwapModule");
  const collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
  const systemDebtEngine = await getProxy(proxyFactory, "SystemDebtEngine");
  const adminControls = await getProxy(proxyFactory, "AdminControls");

  await accessControlConfig.grantRole(await accessControlConfig.BOOK_KEEPER_ROLE(), bookKeeper.address);
  console.log("BookKeeper role granted to bookKeeper");

  await accessControlConfig.grantRole(await accessControlConfig.POSITION_MANAGER_ROLE(), positionManager.address);
  console.log("PositionManager role granted to positionManager");
  await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), positionManager.address);
  console.log("CollateralManager role granted to positionManager");

  await accessControlConfig.grantRole(await accessControlConfig.STABILITY_FEE_COLLECTOR_ROLE(), stabilityFeeCollector.address);
  console.log("StabilityFeeCollector role granted to stabilityFeeCollector");

  await accessControlConfig.grantRole(await accessControlConfig.LIQUIDATION_ENGINE_ROLE(), liquidationEngine.address);
  console.log("LiquidationEngine role granted to liquidationEngine");

  await accessControlConfig.grantRole(await accessControlConfig.LIQUIDATION_ENGINE_ROLE(), fixedSpreadLiquidationStrategy.address);
  console.log("LiquidationEngine role granted to fixedSpreadLiquidationStrategy");
  await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), fixedSpreadLiquidationStrategy.address);
  console.log("CollateralManager role granted to fixedSpreadLiquidationStrategy");

  await accessControlConfig.grantRole(await accessControlConfig.LIQUIDATION_ENGINE_ROLE(), showStopper.address);
  console.log("LiquidationEngine role granted to showStopper");
  await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), showStopper.address);
  console.log("CollateralManager role granted to showStopper");
  await accessControlConfig.grantRole(await accessControlConfig.SHOW_STOPPER_ROLE(), showStopper.address);
  console.log("ShowStopper role granted to showStopper");

  await accessControlConfig.grantRole(await accessControlConfig.PRICE_ORACLE_ROLE(), priceOracle.address);
  console.log("PriceOracle role granted to priceOracle");

  await accessControlConfig.grantRole(accessControlConfig.ADAPTER_ROLE(), collateralTokenAdapter.address);
  console.log("Adapter role granted to collateralTokenAdapter");

  await accessControlConfig.grantRole(await accessControlConfig.MINTABLE_ROLE(), flashMintModule.address);
  console.log("Mintable role granted to flashMintModule");

  // To be sunsetted on xdc mainnet, then to be deprecated
  // await accessControlConfig.grantRole(await accessControlConfig.POSITION_MANAGER_ROLE(), stableSwapModule.address)
  // await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), stableSwapModule.address)

  await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), systemDebtEngine.address);
  console.log("CollateralManager role granted to systemDebtEngine");

  await fathomStablecoin.grantRole(await fathomStablecoin.MINTER_ROLE(), stablecoinAdapter.address);
  console.log("Minter role granted to stablecoinAdapter");

  await accessControlConfig.grantRole(await accessControlConfig.GOV_ROLE(), adminControls.address);
  console.log("Gov role granted to adminControls");

  await bookKeeper.addToWhitelist(stablecoinAdapter.address);
  console.log("StablecoinAdapter whitelisted in bookKeeper");

  await collateralTokenAdapter.addToWhitelist(positionManager.address);
  console.log("PositionManager whitelisted in collateralTokenAdapter");
  await collateralTokenAdapter.addToWhitelist(fixedSpreadLiquidationStrategy.address);
  console.log("FixedSpreadLiquidationStrategy whitelisted in collateralTokenAdapter");
  await collateralTokenAdapter.addToWhitelist(liquidationEngine.address);
  console.log("LiquidationEngine whitelisted in collateralTokenAdapter");
  await collateralTokenAdapter.addToWhitelist(showStopper.address);
  console.log("ShowStopper whitelisted in collateralTokenAdapter");

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Adding roles finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  addRoles,
};
