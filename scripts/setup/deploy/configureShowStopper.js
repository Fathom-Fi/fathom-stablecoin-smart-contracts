const { ethers } = require("hardhat");
const { getProxy } = require("../../../common/proxies");

async function configureShowStopper(deployments) {
  const { log } = deployments;

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

  const showStopper = await getProxy(proxyFactory, "ShowStopper");
  const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
  const liquidationEngine = await getProxy(proxyFactory, "LiquidationEngine");
  const systemDebtEngine = await getProxy(proxyFactory, "SystemDebtEngine");
  const priceOracle = await getProxy(proxyFactory, "PriceOracle");

  await showStopper.setBookKeeper(bookKeeper.address);
  console.log("BookKeeper set on ShowStopper");
  await showStopper.setLiquidationEngine(liquidationEngine.address);
  console.log("LiquidationEngine set on ShowStopper");
  await showStopper.setSystemDebtEngine(systemDebtEngine.address);
  console.log("SystemDebtEngine set on ShowStopper");
  await showStopper.setPriceOracle(priceOracle.address);
  console.log("PriceOracle set on ShowStopper");

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Configuring ShowStopper finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  configureShowStopper,
};
