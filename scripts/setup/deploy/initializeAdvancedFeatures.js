const { ethers } = require("hardhat");

async function initializeAdvancedFeatures(deployments, getChainId) {
  const chainId = await getChainId();
  console.log("🔧 Initializing Advanced Features for chain:", chainId);

  // Get deployed contracts
  const bookKeeper = await deployments.get("BookKeeper");
  const stablecoin = await deployments.get("FathomStablecoin");
  const accessControlConfig = await deployments.get("AccessControlConfig");
  const systemDebtEngine = await deployments.get("SystemDebtEngine");

  const { deployer } = await ethers.getNamedSigners();

  try {
    // Initialize TWAP Price Feed
    console.log("📊 Initializing TWAP Price Feed...");
    const twapPriceFeed = await deployments.get("TWAPPriceFeed");
    const twapContract = await ethers.getContractAt("TWAPPriceFeed", twapPriceFeed.address);
    
    // Example initialization with a base price feed (would need to be configured based on actual deployment)
    // await twapContract.initialize(
    //   basePriceFeedAddress,
    //   accessControlConfig.address,
    //   ethers.utils.formatBytes32String("ETH-A"),
    //   3600, // 1 hour window
    //   300   // 5 minute observation window
    // );

    // Initialize Liquidation Protector
    console.log("🛡️ Initializing Liquidation Protector...");
    const liquidationProtector = await deployments.get("LiquidationProtector");
    const protectorContract = await ethers.getContractAt("LiquidationProtector", liquidationProtector.address);
    
    await protectorContract.initialize(
      bookKeeper.address,
      accessControlConfig.address,
      deployer.address, // Fee recipient
      7200, // 2 hour grace period
      ethers.utils.parseEther("0.05") // 5% max protection fee
    );

    // Initialize Stability Fee Optimizer
    console.log("⚡ Initializing Stability Fee Optimizer...");
    const stabilityOptimizer = await deployments.get("StabilityFeeOptimizer");
    const optimizerContract = await ethers.getContractAt("StabilityFeeOptimizer", stabilityOptimizer.address);
    
    await optimizerContract.initialize(
      bookKeeper.address,
      stablecoin.address,
      bookKeeper.address, // Placeholder for stablecoin price oracle
      3600 // 1 hour update frequency
    );

    // Initialize Vault Insurance Pool
    console.log("🏦 Initializing Vault Insurance Pool...");
    const insurancePool = await deployments.get("VaultInsurancePool");
    const poolContract = await ethers.getContractAt("VaultInsurancePool", insurancePool.address);
    
    await poolContract.initialize(
      bookKeeper.address,
      2000, // 20% reserve ratio
      500,  // 5% staking reward rate
      30 * 24 * 3600 // 30 day claim time limit
    );

    // Initialize Cross Collateral Manager
    console.log("🔗 Initializing Cross Collateral Manager...");
    const crossCollateralManager = await deployments.get("CrossCollateralManager");
    const managerContract = await ethers.getContractAt("CrossCollateralManager", crossCollateralManager.address);
    
    await managerContract.initialize(
      bookKeeper.address,
      ethers.utils.parseEther("1.05") // 105% liquidation threshold
    );

    // Initialize Emergency Coordinator
    console.log("🚨 Initializing Emergency Coordinator...");
    const emergencyCoordinator = await deployments.get("EmergencyCoordinator");
    const coordinatorContract = await ethers.getContractAt("EmergencyCoordinator", emergencyCoordinator.address);
    
    await coordinatorContract.initialize(
      bookKeeper.address,
      true // Auto resolution enabled
    );

    console.log("✅ Advanced Features Initialization Complete!");

  } catch (error) {
    console.error("❌ Error initializing advanced features:", error);
    throw error;
  }
}

module.exports = {
  initializeAdvancedFeatures,
};
