const { ethers } = require("hardhat");
const { BigNumber } = ethers;
const pools = require("../../../common/collateral");
const { getProxy } = require("../../../common/proxies");
const { getConfigInitialCollateral } = require("../../../common/collateral-setup-helper");

const WeiPerWad = BigNumber.from(`1${"0".repeat(18)}`);
const WeiPerRay = BigNumber.from(`1${"0".repeat(27)}`);
const WeiPerRad = BigNumber.from(`1${"0".repeat(45)}`);

async function addCollateralPools(deployments, getChainId) {
  const { log } = deployments;
  const chainId = await getChainId();

  const config = getConfigInitialCollateral(chainId);
  const CLOSE_FACTOR_BPS = BigNumber.from(config.CLOSE_FACTOR_BPS); // <- 0.25
  const LIQUIDATOR_INCENTIVE_BPS = BigNumber.from(config.LIQUIDATOR_INCENTIVE_BPS); // <- 1.05
  const TREASURY_FEE_BPS = BigNumber.from(config.TREASURY_FEE_BPS); // <- 0.8
  const STABILITY_FEE = BigNumber.from(config.STABILITY_FEE);
  const LIQUIDATIONRATIO = WeiPerRay.mul(config.LIQUIDATIONRATIO_NUMERATOR).div(config.LIQUIDATIONRATIO_DENOMINATOR).toString(); // LTV 75%
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
  const simplePriceFeed = await getProxy(proxyFactory, "SimplePriceFeed");
  // CentralizedOraclePriceFeed is commented since it can be used only when Price Aggregator is available
  // For CentralizedOraclePriceFeed to be in use, below apps should be deployed and be active.
  // CentralizedOraclePriceFeed - FathomPrieOracle - Price Aggregator for an Asset - Fathom Oracle infra's price feeder
  // const centralizedOraclePriceFeed = await getProxy(proxyFactory, "CentralizedOraclePriceFeed");
  const collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");

  // initial collateral price as 1 USD
  await simplePriceFeed.setPrice(WeiPerWad.toString());
  console.log("simplePriceFeed price set");
  await simplePriceFeed.setPoolId(pools.NATIVE);
  console.log("simplePriceFeed poolId set");
  await simplePriceFeed.peekPrice();
  console.log("simplePriceFeed peekPrice set");
  // await centralizedOraclePriceFeed.peekPrice({ gasLimit: 2000000 });

  await initPool(pools.NATIVE, collateralTokenAdapter.address, simplePriceFeed.address, LIQUIDATIONRATIO);

  await bookKeeper.setTotalDebtCeiling(debtCeilingSetUpTotal);
  console.log("bookKeeper setTotalDebtCeiling set");

  async function initPool(poolId, adapter, priceFeed, liquidationRatio) {
    await collateralPoolConfig.initCollateralPool(
      poolId,
      debtCeilingSetUp,
      debtFloor, // _debtFloor
      positionDebtCeiling, // _positionDebtCeiling
      priceFeed,
      liquidationRatio,
      STABILITY_FEE,
      adapter,
      CLOSE_FACTOR_BPS,
      LIQUIDATOR_INCENTIVE_BPS,
      TREASURY_FEE_BPS,
      fixedSpreadLiquidationStrategy.address
    );
    console.log("collateralPoolConfig initCollateralPool set");

    await priceOracle.setPrice(poolId);
    console.log("priceOracle setPrice set");
  }

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Adding Collateral Pools Finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  addCollateralPools,
};
