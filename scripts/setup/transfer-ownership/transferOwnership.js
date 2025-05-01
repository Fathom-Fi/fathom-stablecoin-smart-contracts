const { ethers } = require("hardhat");
const { BigNumber } = ethers;

const { getProxy } = require("../../../common/proxies");

async function transferOwnership(getNamedAccounts, deployments, forFixture = false) {
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  const ProxyFactory = await deployments.get("FathomProxyFactory");
  const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

  const ProxyAdmin = await deployments.get("FathomProxyAdmin");
  const proxyAdmin = await ethers.getContractAt("FathomProxyAdmin", ProxyAdmin.address);

  const flashMintArbitrager = await getProxy(proxyFactory, "FlashMintArbitrager");
  const proxyWalletFactory = await getProxy(proxyFactory, "ProxyWalletFactory");
  const bookKeeperFlashMintArbitrager = await getProxy(proxyFactory, "BookKeeperFlashMintArbitrager");
  const accessControlConfig = await getProxy(proxyFactory, "AccessControlConfig");
  const fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
  const stableSwap = await getProxy(proxyFactory, "StableSwapModule");
  const stableSwapModuleWrapper = await getProxy(proxyFactory, "StableSwapModuleWrapper");

  const Timelock = await deployments.get("Timelock");

  // Transfer ownership of FathomProxyFactory to DAO
  await proxyFactory.transferOwnership(Timelock.address);
  // Transfer ownership of FathomProxyAdmin to DAO
  await proxyAdmin.transferOwnership(Timelock.address);
  // Transfer ownership of ProxyWalletFactory to DAO
  // await proxyWalletFactory.transferOwnership(Timelock.address); TODO: issue since owner is not set on ProxyWalletFactory
  // Transfer ownership of FlashMintArbitrager to DAO
  await flashMintArbitrager.transferOwnership(Timelock.address);
  // Transfer ownership of BookKeeperFlashMintArbitrager to DAO
  await bookKeeperFlashMintArbitrager.transferOwnership(Timelock.address);

  if (forFixture) {
    await fathomStablecoin.grantRole(await fathomStablecoin.MINTER_ROLE(), Timelock.address);
    await accessControlConfig.grantRole(await accessControlConfig.PRICE_ORACLE_ROLE(), Timelock.address);
    await accessControlConfig.grantRole(await accessControlConfig.OWNER_ROLE(), Timelock.address);
    await accessControlConfig.grantRole(await accessControlConfig.MINTABLE_ROLE(), Timelock.address);

    await stableSwap.addToWhitelist(Timelock.address);
    await stableSwapModuleWrapper.addToWhitelist(Timelock.address);
  }

  // Grant OWNER_ROLE to DAO
  await accessControlConfig.grantRole(await accessControlConfig.OWNER_ROLE(), Timelock.address);
  // EOA should renounce ownership
  await accessControlConfig.renounceRole(await accessControlConfig.OWNER_ROLE(), deployer);
}

module.exports = {
  transferOwnership,
};
