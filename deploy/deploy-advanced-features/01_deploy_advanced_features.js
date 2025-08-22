// Advanced Features Deployment
const { deployAdvancedFeatures } = require("../../scripts/setup/deploy/deployAdvancedFeatures");
const { initializeAdvancedFeatures } = require("../../scripts/setup/deploy/initializeAdvancedFeatures");

module.exports = async ({ getNamedAccounts, deployments, getChainId }) => {
  console.log("🚀 Starting Advanced Features Deployment...");
  
  // Deploy the advanced feature contracts
  await deployAdvancedFeatures(getNamedAccounts, deployments);
  
  // Initialize the advanced features
  await initializeAdvancedFeatures(deployments, getChainId);
  
  console.log("✅ Advanced Features Deployment Complete!");
};

module.exports.tags = ["DeployAdvancedFeatures"];
module.exports.dependencies = ["DeployMain"]; // Ensure main contracts are deployed first
