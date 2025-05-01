// Setup
const { deployMocks } = require("../../scripts/setup/deploy-test-fixture/deployMocks");
const { deployContracts } = require("../../scripts/setup/deploy/deployContracts");
const { deployProxies } = require("../../scripts/setup/deploy/deployProxies");
const { initialize } = require("../../scripts/setup/deploy/initialize");
const { addRoles } = require("../../scripts/setup/deploy/addRoles");
const { configureFees } = require("../../scripts/setup/deploy/configureFees");
const { configureShowStopper } = require("../../scripts/setup/deploy/configureShowStopper");
const { deployVault } = require("../../scripts/setup/deploy/deployVault");
const { initCollateralTokenAdapter } = require("../../scripts/setup/deploy/initCollateralTokenAdapter");
const { configFlashLending } = require("../../scripts/setup/deploy/configFlashLending");
const { deployMocksPostDeployment } = require("../../scripts/setup/deploy-test-fixture/deployMocksPostDeployment");
const { addCollateralPreDeployment } = require("../../scripts/setup/deploy-test-fixture/addCollateralPreDeployment");

// Configuration
const { addRoles: addRolesTestFixture } = require("../../scripts/configuration/deploy-test-fixture/addRoles");
const { addCollateralPools } = require("../../scripts/configuration/deploy-test-fixture/addCollateralPools");
const { addCollateralPoolsPostDeployment } = require("../../scripts/configuration/deploy-test-fixture/addCollateralPoolsPostDeployment");
const { addRolesPostDeployment } = require("../../scripts/configuration/deploy-test-fixture/addRolesPostDeployment");
const { addCollateralConfigPool } = require("../../scripts/configuration/deploy-test-fixture/addCollateralConfigPool");

// Add collateral
const { deploy } = require("../../scripts/setup/add-collateral/deploy");
const { deployProxies: deployProxiesAddCollateral } = require("../../scripts/setup/add-collateral/deployProxies");
const { initialize: initializeAddCollateral } = require("../../scripts/setup/add-collateral/initialize");
const { addRoles: addRolesAddCollateral } = require("../../scripts/setup/add-collateral/addRoles");
const { deployVault: deployVaultAddCollateral } = require("../../scripts/setup/add-collateral/deployVault");

const { updateBookKeeper } = require("../../scripts/configuration/update-book-keeper/updateBookKeeper");

module.exports = async ({ getNamedAccounts, deployments, getChainId }) => {
  // Setup
  await deployMocks(getNamedAccounts, deployments, getChainId);
  await deployContracts(getNamedAccounts, deployments, getChainId);
  await deployProxies(deployments, getChainId);
  await initialize(deployments, getChainId, true);
  await addRoles(deployments, getChainId);
  await configureFees(deployments);
  await configureShowStopper(deployments);
  await deployVault(getNamedAccounts, deployments, getChainId, true);
  await initCollateralTokenAdapter(deployments);
  await configFlashLending(deployments);

  // Configuration
  await addRolesTestFixture(getNamedAccounts, deployments);
  await addCollateralPools(deployments);

  // POST_DEPLOYMENT
  // Setup
  await deployMocksPostDeployment(getNamedAccounts, deployments, getChainId);
  // Configuration
  await addCollateralPoolsPostDeployment(deployments);
  await addRolesPostDeployment(deployments);

  // Add new collateral flow
  // Setup
  await addCollateralPreDeployment(getNamedAccounts, deployments, getChainId);

  // Add collateral
  await deploy(getNamedAccounts, deployments, getChainId);
  await deployProxiesAddCollateral(deployments, getChainId, true);
  await initializeAddCollateral(getChainId, true);
  await addRolesAddCollateral(getChainId, true);
  await deployVaultAddCollateral(getNamedAccounts, deployments, getChainId, true);

  // Configuration
  await addCollateralConfigPool(deployments, getChainId);

  // Update BookKeeper
  await updateBookKeeper(getNamedAccounts, deployments);
};

module.exports.tags = ["DeployTestFixture"];
