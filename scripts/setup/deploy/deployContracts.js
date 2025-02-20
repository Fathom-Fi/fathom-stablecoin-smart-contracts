async function deployContracts(getNamedAccounts, deployments) {
  const { deploy, log } = deployments;
  const { deployer } = await getNamedAccounts();

  await deploy("AccessControlConfig", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("CollateralPoolConfig", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("BookKeeper", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("FathomStablecoin", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("SystemDebtEngine", {
    from: deployer,
    args: [],
    log: true,
  });
  // To be sunsetted on xdc mainnet, then to be deprecated
  // await deploy("StableSwapModule", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  // Contracts that get prices from DEX are not longer in need
  // await deploy("DexPriceOracle", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  // await deploy("SlidingWindowDexOracle", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  await deploy("ProxyWalletRegistry", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("ProxyWalletFactory", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("StabilityFeeCollector", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("FathomStablecoinProxyActions", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("FixedSpreadLiquidationStrategy", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("PositionManager", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("ShowStopper", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("PriceOracle", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("FathomPriceOracle", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("StablecoinAdapter", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("LiquidationEngine", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("FlashMintModule", {
    from: deployer,
    args: [],
    log: true,
  });
  // await deploy("FlashMintArbitrager", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  // await deploy("BookKeeperFlashMintArbitrager", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  await deploy("FathomProxyFactory", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("FathomProxyAdmin", {
    from: deployer,
    args: [],
    log: true,
  });
  // await deploy("DelayFathomOraclePriceFeed", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  await deploy("CollateralTokenAdapter", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("ProxyActionsStorage", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("AdminControls", {
    from: deployer,
    args: [],
    log: true,
  });
  await deploy("CentralizedOraclePriceFeed", {
    from: deployer,
    args: [],
    log: true,
  });
  // To be sunsetted on xdc mainnet, then to be deprecated
  // await deploy("StableSwapModuleWrapper", {
  //   from: deployer,
  //   args: [],
  //   log: true,
  // });
  await deploy("SimplePriceFeed", {
    from: deployer,
    args: [],
    log: true,
  });

  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  log("Deploying Contracts Finished");
  log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
}

module.exports = {
  deployContracts,
};
