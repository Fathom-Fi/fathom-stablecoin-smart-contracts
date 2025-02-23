require("dotenv").config({ path: __dirname + "/.env" });
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-deploy");
require("./tasks/price-feed");
require("./tasks/fathom-solidity-sdk");
require("./tasks/stable-swap-info");
require("./tasks/cancel-stable-swap");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {
      accounts: {
        mnemonic: process.env.SEED_PHRASE,
      },
      gasPrice: 1000000000,
    },
    apothem: {
      // Please check the status of RPC URL in below link.
      // https://chainlist.org/?search=native
      url: "https://erpc.apothem.network/",
      // url: "https://rpc.apothem.network/",
      accounts: {
        mnemonic: process.env.SEED_PHRASE,
      },
      gasPrice: 1000000000,
    },
    xdc: {
      // Please check the status of RPC URL in below link.
      // https://chainlist.org/?search=native
      url: "https://erpc.xdcrpc.com",
      accounts: {
        mnemonic: process.env.SEED_PHRASE,
      },
      gasPrice: 1000000000,
    },
  },
  solidity: {
    version: "0.8.17",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "istanbul",
      outputSelection: {
        "*": {
          "*": ["storageLayout"],
        },
      },
    },
  },
  namedAccounts: {
    deployer: 0,
    allice: 1,
    bob: 2,
    dev: 3,
    treasury: 4,
    a0: "0x0000000000000000000000000000000000000000",
    a1: "0x0000000000000000000000000000000000000001",
    a2: "0x0000000000000000000000000000000000000002",
    apothemDeployerTest: "0xB4A0403376CA4f0a99b863840EfFf78bc061d71F",
  },
};
