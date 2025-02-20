require("dotenv").config({ path: __dirname + "/.env" });
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-deploy");
require("./tasks/switch-price-feed");
require("./tasks/whitelist-col-token-adapter");
require("./tasks/remove-whitelist-col-token-adapter");
require("./tasks/whitelist-fmm");
require("./tasks/add-roles");
require("./tasks/revoke-roles");
require("./tasks/transfer-protocol-ownership");
require("./tasks/transfer-proxy-admin-ownership");
require("./tasks/fee-collection");

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
    "lisk-sepolia": {
      chainId: 4202,
      // Please check the status of RPC URL in below link.
      // https://chainlist.org/?search=native
      url: "https://rpc.sepolia-api.lisk.com",
      accounts: {
        mnemonic: process.env.SEED_PHRASE,
      },
      gasPrice: 1000000000,
    },
    lisk: {
      chainId: 1135,
      // Please check the status of RPC URL in below link.
      // https://chainlist.org/?search=native
      url: "https://rpc.api.lisk.com",
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
  etherscan: {
    // Use "123" as a placeholder, because Blockscout doesn't need a real API key, and Hardhat will complain if this property isn't set.
    apiKey: {
      "lisk-sepolia": "123",
    },
    customChains: [
      {
        network: "lisk-sepolia",
        chainId: 4202,
        urls: {
          apiURL: "https://sepolia-blockscout.lisk.com/api",
          browserURL: "https://sepolia-blockscout.lisk.com",
        },
      },
    ],
  },
  sourcify: {
    enabled: false,
  },
};
