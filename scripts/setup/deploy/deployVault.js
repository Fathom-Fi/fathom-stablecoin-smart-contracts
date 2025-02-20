const { ethers } = require("hardhat");
const { getAddresses } = require("../../../common/addresses");
const { getProxy } = require("../../../common/proxies");
const pools = require("../../../common/collateral");

async function deployVault(getNamedAccounts, deployments, getChainId, forFixture = false) {
  const chainId = await getChainId();
  const addresses = getAddresses(chainId);
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

  const collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
  let wnativeAddress;
  if (forFixture) {
    const WNATIVE = await deployments.get("WNATIVE");
    wnativeAddress = WNATIVE.address;
  } else {
    wnativeAddress = addresses.WNATIVE;
  }
  await deploy("Vault", {
    from: deployer,
    args: [pools.NATIVE, wnativeAddress, collateralTokenAdapter.address],
    log: true,
  });

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Deploying Vault finished!");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  deployVault,
};
