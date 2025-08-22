async function deployAdvancedFeatures(getNamedAccounts, deployments) {
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  console.log("🚀 Deploying Advanced Stablecoin Features...");

  // Deploy TWAP Price Feed
  console.log("📊 Deploying TWAP Price Feed...");
  await deploy("TWAPPriceFeed", {
    from: deployer,
    args: [],
    log: true,
  });

  // Deploy Liquidation Protector
  console.log("🛡️ Deploying Liquidation Protector...");
  await deploy("LiquidationProtector", {
    from: deployer,
    args: [],
    log: true,
  });

  // Deploy Stability Fee Optimizer
  console.log("⚡ Deploying Stability Fee Optimizer...");
  await deploy("StabilityFeeOptimizer", {
    from: deployer,
    args: [],
    log: true,
  });

  // Deploy Vault Insurance Pool
  console.log("🏦 Deploying Vault Insurance Pool...");
  await deploy("VaultInsurancePool", {
    from: deployer,
    args: [],
    log: true,
  });

  // Deploy Cross Collateral Manager
  console.log("🔗 Deploying Cross Collateral Manager...");
  await deploy("CrossCollateralManager", {
    from: deployer,
    args: [],
    log: true,
  });

  // Deploy Emergency Coordinator
  console.log("🚨 Deploying Emergency Coordinator...");
  await deploy("EmergencyCoordinator", {
    from: deployer,
    args: [],
    log: true,
  });

  console.log("✅ Advanced Features Deployment Complete!");
}

module.exports = {
  deployAdvancedFeatures,
};
