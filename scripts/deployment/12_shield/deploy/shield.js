const fs = require('fs');

const rawdata = fs.readFileSync('./addresses.json');

let stablecoinAddress = JSON.parse(rawdata);

async function main() {

  const signers = await ethers.getSigners()

  
  console.log(">> Deploying an not upgradable Shield contract")

  const Shield = await hre.ethers.getContractFactory("Shield");
  const shield = await Shield.deploy(signers[0].address, stablecoinAddress.fairLaunch)
  await shield.deployed()

  console.log(`>> Deployed at ${shield.address}`)
  const tx = await shield.deployTransaction.wait()
  console.log(`>> Deploy block ${tx.blockNumber}`)

  let addressesUpdate = { 
    shield: shield.address,
  };

  const newAddresses = {
    ...stablecoinAddress,  
    ...addressesUpdate
  };

  const newData = JSON.stringify(newAddresses);
  fs.writeFile("./addresses.json", newData, err => {
    if(err) throw err;
    console.log("New address added");
  })
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
