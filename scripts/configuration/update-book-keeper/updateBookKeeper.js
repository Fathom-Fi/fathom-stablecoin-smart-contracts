const { ethers } = require("hardhat");
const { getProxy } = require("../../../common/proxies");

async function updateBookKeeper(getNamedAccounts, deployments) {
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

  const ProxyAdmin = await deployments.get("FathomProxyAdmin");
  const proxyAdmin = await ethers.getContractAt("FathomProxyAdmin", ProxyAdmin.address);

  await deploy("BookKeeperV2", {
    from: deployer,
    args: [],
    log: true,
  });

  const BookKeeperV2 = await deployments.get("BookKeeperV2");

  const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
 
  log("BookKeeper Proxy address: ", bookKeeper.address);
  log("BookKeeper Proxy current implementation address: ", await proxyAdmin.getProxyImplementation(bookKeeper.address));
  log("BookKeeperV2 implementation address: ", BookKeeperV2.address);
  await proxyAdmin.upgrade(bookKeeper.address, BookKeeperV2.address);
  log("Upgrading BookKeeper to BookKeeperV2");
  log("BookKeeper Proxy new implementation address: ", await proxyAdmin.getProxyImplementation(bookKeeper.address));
}
  
module.exports = {
  updateBookKeeper,
};
  