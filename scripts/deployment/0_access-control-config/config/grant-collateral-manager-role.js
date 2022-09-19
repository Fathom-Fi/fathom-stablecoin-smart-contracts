const fs = require('fs');

const rawdata = fs.readFileSync('./addresses.json');
let stablecoinAddress = JSON.parse(rawdata);

async function main() {

  const ADDR = stablecoinAddress.fixedSpreadLiquidationStrategy;
  const ADDR2 = stablecoinAddress.positionManager;


  const AccessControlConfig = await hre.ethers.getContractFactory("AccessControlConfig");
  const accessControlConfig = await AccessControlConfig.attach(stablecoinAddress.accessControlConfig);

  console.log(`>> Grant COLLATERAL_MANAGER_ROLE address: ${ADDR}`)
  console.log(`>> Grant COLLATERAL_MANAGER_ROLE address: ${ADDR2}`)
  await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), ADDR)
  await accessControlConfig.grantRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), ADDR2)
  console.log("✅ Done")

}
// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});