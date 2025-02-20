const { ethers } = require("hardhat");
const { getProxy } = require("../../../common/proxies");

async function configFlashLending(deployments) {
  const { log } = deployments;
  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

  const fixedSpreadLiquidationStrategy = await getProxy(proxyFactory, "FixedSpreadLiquidationStrategy");

  await fixedSpreadLiquidationStrategy.setFlashLendingEnabled(true);
  console.log("Flash lending enabled on FixedSpreadLiquidationStrategy");

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Configuring flash lending finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

module.exports = {
  configFlashLending,
};
