const { getProxy, getProxyById } = require("../../../common/proxies");
const { getConfigAddCollateral } = require("../../../common/collateral-setup-helper");
const { getConfig, getProxyId, poolId } = require("../../../common/add-collateral-helper")

const { BigNumber } = require("ethers");
const WeiPerWad = BigNumber.from(`1${"0".repeat(18)}`)
const WeiPerRay = BigNumber.from(`1${"0".repeat(27)}`)
const WeiPerRad = BigNumber.from(`1${"0".repeat(45)}`)


module.exports = async function (deployer) {
    const config = getConfig(deployer.networkId());
    const config2 = getConfigAddCollateral(deployer.networkId());

    const CLOSE_FACTOR_BPS = BigNumber.from(config2.CLOSE_FACTOR_BPS)   // <- 0.25
    const LIQUIDATOR_INCENTIVE_BPS = BigNumber.from(config2.LIQUIDATOR_INCENTIVE_BPS)  // <- 1.05
    const TREASURY_FEE_BPS = BigNumber.from(config2.TREASURY_FEE_BPS) // <- 0.8
    const STABILITY_FEE = BigNumber.from(config2.STABILITY_FEE)
    const LIQUIDATIONRATIO = WeiPerRay.mul(config2.LIQUIDATIONRATIO_NUMERATOR).div(config2.LIQUIDATIONRATIO_DENOMINATOR).toString(); // LTV 75%
    const debtCeilingSetUpTotal = WeiPerRad.mul(config2.DEBTCELINGSETUP_TOTAL);
    const debtCeilingSetUp = WeiPerRad.mul(config2.DEBTCELINGSETUP_NUMERATOR).div(config2.DEBTCELINGSETUP_DENOMINATOR);
    const debtFloor = WeiPerRad.mul(config2.DEBT_FLOOR);
    const positionDebtCeiling = WeiPerRad.mul(config2.POSITION_DEBT_CEILING);

    const proxyFactory = await artifacts.initializeInterfaceAt("FathomProxyFactory", config.fathomProxyFactory);
    const collateralTokenAdapter = await getProxyById(proxyFactory, "CollateralTokenAdapter", getProxyId("CollateralTokenAdapter"));
    const fixedSpreadLiquidationStrategy = config2.FIXED_SPREAD_LIQUIDATION_STRATEGY;
    const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig")
    const priceOracle = await getProxy(proxyFactory, "PriceOracle")

    // const simplePriceFeed = await getProxy(proxyFactory, "SimplePriceFeed");
    // 2024.05.23 simplePriceFeed should be the one that's been recently deployed. so use below line instead of getProxy
    const simplePriceFeedNewCol = await artifacts.initializeInterfaceAt("SimplePriceFeedNewCol", "SimplePriceFeedNewCol");
    const accessControlConfig = await getProxy(proxyFactory, "AccessControlConfig");

    await simplePriceFeedNewCol.initialize(accessControlConfig.address);
    await simplePriceFeedNewCol.setPoolId(poolId);
    await simplePriceFeedNewCol.setPrice(WeiPerWad.toString());

    const priceFeed = simplePriceFeedNewCol;
=
    const priceFeed = await getProxyById(proxyFactory, "CentralizedOraclePriceFeed", getProxyId("CentralizedOraclePriceFeed"));
    await priceFeed.peekPrice({ gasLimit: 2000000 });

    await collateralPoolConfig.initCollateralPool(
        poolId,
        debtCeilingSetUp,
        debtFloor,
        positionDebtCeiling,
        priceFeed.address,
        LIQUIDATIONRATIO,
        STABILITY_FEE,
        collateralTokenAdapter.address,
        CLOSE_FACTOR_BPS,
        LIQUIDATOR_INCENTIVE_BPS,
        TREASURY_FEE_BPS,
        fixedSpreadLiquidationStrategy,
        { gas: 5000000 }
    )

    await priceOracle.setPrice(poolId, { gasLimit: 2000000 });
}