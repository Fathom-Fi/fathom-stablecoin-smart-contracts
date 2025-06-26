const { ethers } = require("hardhat");
const provider = ethers.provider;
const { smock } = require("@defi-wonderland/smock");

const { formatBytes32String } = ethers.utils;

const deployFixtures = async () => {
  const { allice } = await getNamedAccounts();
  const AliceAddress = allice;

  const mockedAccessControlConfig = await smock.fake("AccessControlConfig");
  const mockedCollateralPoolConfig = await smock.fake("CollateralPoolConfig");
  const mockedVault = await smock.fake("Vault");

  const mockedBookKeeper = await smock.fake("BookKeeper");
  
  // Create a real 9 decimals token for testing
  const ERC20Mintable9DecimalsFactory = await ethers.getContractFactory("ERC20Mintable9Decimals");
  const mockedToken = await ERC20Mintable9DecimalsFactory.deploy("Test Token 9", "TT9");
  await mockedToken.deployed();

  mockedAccessControlConfig.OWNER_ROLE.returns(formatBytes32String("OWNER_ROLE"));
  mockedAccessControlConfig.GOV_ROLE.returns(formatBytes32String("GOV_ROLE"));
  mockedAccessControlConfig.SHOW_STOPPER_ROLE.returns(formatBytes32String("SHOW_STOPPER_ROLE"));
  mockedAccessControlConfig.hasRole.returns(true);

  const TokenAdapterFactory = await ethers.getContractFactory("TokenAdapter");
  const tokenAdapter = await TokenAdapterFactory.deploy();
  await tokenAdapter.deployed();

  const tokenAdapterAsAlice = tokenAdapter.connect(provider.getSigner(AliceAddress));

  await tokenAdapter.initialize(mockedBookKeeper.address, formatBytes32String("BTCB"), mockedToken.address);

  return {
    tokenAdapter,
    tokenAdapterAsAlice,
    mockedBookKeeper,
    mockedToken,
    mockedAccessControlConfig,
    mockedCollateralPoolConfig,
    mockedVault,
  };
};

module.exports = {
  deployFixtures,
};
