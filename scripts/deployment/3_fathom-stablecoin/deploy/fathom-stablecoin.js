const fs = require('fs');

const FathomStablecoin = artifacts.require('./8.17/stablecoin-core/FathomStablecoin.sol');

const rawdata = fs.readFileSync('../../../../addresses.json');
let stablecoinAddress = JSON.parse(rawdata);

module.exports =  async function(deployer) {
  console.log(">> Deploying an upgradable FathomStablecoin contract")

  let promises = [
      deployer.deploy(FathomStablecoin, { gas: 4050000 }),
  ];

  await Promise.all(promises);

  const deployed = artifacts.require('./8.17/stablecoin-core/FathomStablecoin.sol');

  let addressesUpdate = { 
    fathomStablecoin:deployed.address,
  };

  const newAddresses = {
    ...stablecoinAddress,  
    ...addressesUpdate
  };

  let data = JSON.stringify(newAddresses);
  fs.writeFileSync('./addresses.json', data);
};
