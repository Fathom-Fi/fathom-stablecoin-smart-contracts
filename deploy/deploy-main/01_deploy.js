// Setup
const { deployContracts } = require("../../scripts/setup/deploy/deployContracts");
const { deployProxies } = require("../../scripts/setup/deploy/deployProxies");
const { initialize } = require("../../scripts/setup/deploy/initialize");
const { addRoles } = require("../../scripts/setup/deploy/addRoles");
const { configureFees } = require("../../scripts/setup/deploy/configureFees");
const { configureShowStopper } = require("../../scripts/setup/deploy/configureShowStopper");
const { deployVault } = require("../../scripts/setup/deploy/deployVault");
const { initCollateralTokenAdapter } = require("../../scripts/setup/deploy/initCollateralTokenAdapter");
const { configFlashLending } = require("../../scripts/setup/deploy/configFlashLending");
const { deployDao } = require("../../scripts/setup/deploy/deployDao");
const { transferOwnership } = require("../../scripts/setup/transfer-ownership/transferOwnership");

// Configuration
const { addCollateralPools } = require("../../scripts/configuration/deploy/addCollateralPools");

module.exports = async ({ getNamedAccounts, deployments, getChainId }) => {
  // Setup
  await deployContracts(getNamedAccounts, deployments, getChainId);
  await deployProxies(deployments, getChainId);
  await initialize(deployments, getChainId);
  await addRoles(deployments, getChainId);
  await configureFees(deployments);
  await configureShowStopper(deployments);
  await deployVault(getNamedAccounts, deployments, getChainId);
  await initCollateralTokenAdapter(deployments);
  await configFlashLending(deployments);

  // Configuration
  await addCollateralPools(deployments, getChainId);

  //Transfer ownership of the contracts to the dao
  await deployDao(getNamedAccounts, deployments);
  await transferOwnership(getNamedAccounts, deployments);
};

module.exports.tags = ["DeployMain"];
