const fs = require('fs');

const BookKeeper = artifacts.require('./8.17/stablecoin-core/BookKeeper.sol');

const rawdata = fs.readFileSync('../../../../addresses.json');
let stablecoinAddress = JSON.parse(rawdata);

module.exports =  async function(deployer) {

  console.log(">> Deploying an upgradable BookKeeper contract")
  let promises = [
      deployer.deploy(BookKeeper, { gas: 4050000 }),
  ];

  await Promise.all(promises);

  const deployed = artifacts.require('./8.17/stablecoin-core/BookKeeper.sol');

  let addressesUpdate = { 
    bookKeeper:deployed.address,
  };

  const newAddresses = {
    ...stablecoinAddress,  
    ...addressesUpdate
  };

  let data = JSON.stringify(newAddresses);
  fs.writeFileSync('./addresses.json', data);
};
