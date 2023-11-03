const fs = require('fs');
const { BigNumber } = require('ethers');

const rawdata = fs.readFileSync('../../../../externalAddresses.json');
let addresses = JSON.parse(rawdata);

const MockedDexRouter = artifacts.require('MockedDexRouter.sol');
const TokenAdapter = artifacts.require('TokenAdapter.sol');
const FathomToken = artifacts.require('FathomToken.sol');
const ERC20 = artifacts.require('ERC20Mintable.sol');
const WXDC = artifacts.require('WXDC.sol');
const SimplePriceFeed = artifacts.require('SimplePriceFeed.sol')
const StableswapMultipleSwapsMock = artifacts.require("StableswapMultipleSwapsMock");
const PluginOracleMock = artifacts.require("PluginOracleMock");

module.exports = async function (deployer) {
  const promises = [
    deployer.deploy(ERC20, "xUSDT", "xUSDT", { gas: 3050000 }),
    deployer.deploy(MockedDexRouter, { gas: 3050000 }),
    deployer.deploy(TokenAdapter, { gas: 3050000 }),
    deployer.deploy(FathomToken, 88, 89, { gas: 3050000 }),
    deployer.deploy(SimplePriceFeed, { gas: 7050000 }),
    deployer.deploy(PluginOracleMock, 1000, { gas: 7050000 })
  ];

  await Promise.all(promises);

  const chainId = deployer.networkId(ERC20.address);
  addresses[chainId].USD = ERC20.address;

  await deployer.deploy(WXDC, { gas: 3050000 }),
    addresses[chainId].WXDC = WXDC.address;
  addresses[chainId].PluginOracle = PluginOracleMock.address;

  await deployer.deploy(StableswapMultipleSwapsMock, { gas: 3050000 })
  fs.writeFileSync('./externalAddresses.json', JSON.stringify(addresses));
};