const fs = require('fs');

const rawdata = fs.readFileSync('./addresses.json');
let stablecoinAddress = JSON.parse(rawdata);

async function main() {

  const BOOK_KEEPER_ADDR = stablecoinAddress.bookKeeper

  const AccessControlConfig = await hre.ethers.getContractFactory("AccessControlConfig");
  const accessControlConfig = await AccessControlConfig.attach(stablecoinAddress.accessControlConfig);

  console.log(`>> Grant BOOK_KEEPER_ROLE address: ${BOOK_KEEPER_ADDR}`)
  await accessControlConfig.grantRole(await accessControlConfig.BOOK_KEEPER_ROLE(), BOOK_KEEPER_ADDR)
  console.log("✅ Done")

}
// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});