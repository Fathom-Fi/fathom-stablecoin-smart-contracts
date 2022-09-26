const fs = require('fs');

const ProxyWalletRegistry = artifacts.require('./8.17/proxy-wallet/ProxyWalletRegistry.sol');

const rawdata = fs.readFileSync('../../../../addresses.json');
let stablecoinAddress = JSON.parse(rawdata);

module.exports =  async function(deployer) {

  console.log(">> Deploying an upgradable ProxyWalletRegistry contract")
  let promises = [
      deployer.deploy(ProxyWalletRegistry, { gas: 4050000 }),
  ];

  await Promise.all(promises);

  const deployed = artifacts.require('./8.17/proxy-wallet/ProxyWalletRegistry.sol');


  let addressesUpdate = { 
    proxyWalletRegistry:deployed.address,
  };

  const newAddresses = {
    ...stablecoinAddress,  
    ...addressesUpdate
  };

  let data = JSON.stringify(newAddresses);
  fs.writeFileSync('./addresses.json', data);
};