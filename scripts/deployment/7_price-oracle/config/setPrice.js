const fs = require('fs');
// const rawdata = fs.readFileSync('../../../../addresses.json');
// let stablecoinAddress = JSON.parse(rawdata);
const { formatBytes32String } = require("ethers/lib/utils");

const COLLATERAL_POOL_ID = formatBytes32String("WXDC")

const PriceOracle = artifacts.require('./8.17/stablecoin-core/PriceOracle.sol');

module.exports =  async function(deployer) {
  console.log(">> Initializing PriceOracle")

  const priceOracle = await PriceOracle.at(stablecoinAddress.priceOracle);


  await priceOracle.setPrice(
    COLLATERAL_POOL_ID
  )

};