# Fathom Stablecoin

FXD is a stablecoin intended to maintain a soft peg to the US Dollar. Its value is meant to stay stable, with minor fluctuations permitted around the target price.

Users may borrow FXD once they obtain the necessary borrowing power via the collateralization mechanism. The primary source of borrowing power in the Fathom Protocol comes from depositing Native coin as collateral.

Various mechanisms, including price oracles, Stable Swap, and a risk management system, preserve the stability of FXD.

![FXD Key Features](https://i.imgur.com/yPPkWpN.jpg)

## Package version requirements for your machine:

- node v20.17.0
- npm v10.8.2
- Hardhat v^2.22.12

## Basic setup

The smart contracts are written in [Solidity](https://github.com/ethereum/solidity) and tested/deployed using [Hardhat](https://hardhat.org/).

### Install nodejs:

```bash
$ sudo apt install nodejs
```

### Install npm:

```bash
$ sudo apt install npm
```

## Running tests

### 0) After cloning the repo, install dependencies

```bash
$ npm i
```

### 1) Create SEED_PHRASE environment variable:

```bash
$ echo -n SEED_PHRASE=12_WORD_MNEMONIC > .env
```

### 2) Create externalAddresses.json file in root

The chainId 31337 WNATIVE address is required to execute the test scripts on built-in Hardhat Network. Zero addresses must be included in the externalAddresses.json file as placeholder addresses for test execution. Use the content provided below for the externalAddresses.json file to run the test scripts.

```JSON
{
  "51": { "WNATIVE": "0x82b4334F5CD8385f55969BAE0A863a0C6eA9F63f" },
  "17000": { "WNATIVE": "0x94373a4919B3240D86eA41593D5eBa789FEF3848" },
  "31337": { "WNATIVE": "0x0000000000000000000000000000000000000000" }
}

```

### 3) Create add-collateral.json file in root

```JSON
{
  "50": {
    "tokenAddress": "0x8f9920283470f52128bf11b0c14e798be704fd15",
    "testOracle": "0x0000000000000000000000000000000000000000",
    "fathomProxyFactory": "0x0acf88Ba60561372Ef93a67E04e1A55d9fC1D910",
    "fathomProxyAdmin": "0xb82AD475fc113671840D510B60Cbae5630a07f3B",
    "fixedSpreadLiquidationStrategy": "0xfe5037504E0EF5eC2DfBEEA03f9d9cB43580EF23"
  },
  "51": {
    "tokenAddress": "0x97EC6730Fd5F138fCB167cb62A9a4c1A8Be2eD7d",
    "testOracle": "0x0000000000000000000000000000000000000000",
    "fathomProxyFactory": "0xf62f41d00EAaf02fD31FA24C5630C9AcfEf8D69F",
    "fathomProxyAdmin": "0x6B33e88ec42291Bf82C9E7CE7f45DdC3464897bf",
    "fixedSpreadLiquidationStrategy": "0x4bEb8638AFe2892Fa7D46303F60f22e106C9AB7B"
  },
  "31337": {
    "tokenAddress": "0x0000000000000000000000000000000000000000",
    "testOracle": "0x0000000000000000000000000000000000000000",
    "fathomProxyFactory": "0x0000000000000000000000000000000000000000",
    "fathomProxyAdmin": "0x0000000000000000000000000000000000000000",
    "fixedSpreadLiquidationStrategy": "0x0000000000000000000000000000000000000000"
  },
  "token": "GLD"
}

```

### 4) Run commands to run tests in root

```bash
$ npm run test
```

The contracts will compile, be deployed, and then the test scripts will run.

To run a specific test script instead of running the the whole tests, run as below. For example, to run PositionPermissions.test.js

```bash
$ npx hardhat test test/integration/AdminControls.test.js
```

## Deployment

The current codebase is structured so that the same set of smart contracts will be deployed, regardless of the target blockchain. By default, the protocol's price feed after deployment is set to `SimplePriceFeed`, a mock price feed that allows the protocol's deployer (owner) to freely modify prices. This default setting is based on the consideration that other price feeds for commercial use require external addresses or even price-related bots for successful deployment. Consequently, the adjusted deployment/migration script will deploy `CentralizedOraclePriceFeed`, 'FathomPriceOracle' using proxy patterns, but only CentralizedOraclePriceFeed will be initialize. Documentation regarding price feed changes will be included in this markdown document following the deployment section.

### On built-in Hardhat network, Chain id: 31337

### 0) Create SEED_PHRASE environment variable:

```bash
$ echo -n SEED_PHRASE=12_WORD_MNEMONIC > .env
```

#### 1) Create externalAddresses.json in root directory.

The format of the content should differ from the one in the Running test sections, with the difference being that we can't use zero address for WNATIVE on chain 31337
WNATIVE address will be the collateralToken address for the initial collateral NAITVE coin of the network that you deploy fathomStablecoin to.

```JSON
{
  "51": { "WNATIVE": "0x82b4334F5CD8385f55969BAE0A863a0C6eA9F63f" },
  "17000": { "WNATIVE": "0x94373a4919B3240D86eA41593D5eBa789FEF3848" },
  "31337": { "WNATIVE": "0xf72f1a39ae0736Ef6A532605C85aFB0A4E349714" }
}

```

If you want to see the protocol in action by depositing test ETH and borrowing FXD, I recommend that you first deploy WNATIVE||WETH on Hardhat Network. After that, update the WNATIVE address in the externalAddresses.json file with the address of the WNATIVE you deployed.

#### 2) Compile contracts

```bash
$ npm run compile
```

make sure that the contracts compile before deployment

#### 3) Deploy with below command

```bash
$ npm run deploy-local
```

#### 4) Check contract addresses in addresses.json file in root

After deployment, addresses.json gets updated with addresses of proxies.

### On apothem (NATIVE Testnet) (chainID 51)

#### 0) Create SEED_PHRASE environment variable (12 word phrase of the wallet that holds the EOA that you would like to deploy contracts from):

```bash
$ echo -n SEED_PHRASE=12_WORD_MNEMONIC > .env
```

#### 1) Create externalAddresses.json in root directory.:

ChainID of apothem is 51. Therefore, the externalAddresses.json need to have the sets of addresses having 51 as key. For example, like below.

```JSON
{
  "51": {
    "WNATIVE": "0xE99500AB4A413164DA49Af83B9824749059b46ce"
  }
}
```

The WNATIVE address above is officially deployed on the Apothem network. Therefore, I recommend using this address unless you have already deployed or are willing to deploy a new WNATIVE address for your testing purposes.

#### 2) Compile contracts

```bash
$ npm run compile
```

make sure that the contracts compile before deployment

#### 3) Deploy with below command

```bash
$ npm run deploy-apothem
```

#### 4) Check contract addresses in addresses.json file in root

After deployment, addresses.json gets updated with addresses of proxies.

### On NATIVE (XDC) mainnet (chainID 50)

#### 0) Create SEED_PHRASE environment variable (12 word phrase of the wallet that holds the EOA that you would like to deploy contracts from):

```bash
$ echo -n SEED_PHRASE=12_WORD_MNEMONIC > .env
```

#### 2) Create externalAddresses.json in root directory.:

ChainID of NATIVE mainnet is 50. Therefore, the externalAddresses.json need to have the sets of addresses having 50 as key. For example, like below.

```JSON
{
  "50": {
    "WNATIVE": "0xE99500AB4A413164DA49Af83B9824749059b46ce"
  }
}
```

WNATIVE is recommended to have the official WNATIVE address unless you would like to use other wrapper contracts.

#### 4) Compile contracts

```bash
$ npm run compile
```

make sure that the contracts compile before deployment

#### 5) Deploy with below command

```bash
$ npm run deploy-xdc
```

#### 6) Check contract addresses in addresses.json file in root

After deployment, addresses.json gets updated with addresses of proxies.

### On Lisk Sepolia Testnet (chainID 4202)

#### 0) Create SEED_PHRASE environment variable (12 word phrase of the wallet that holds the EOA that you would like to deploy contracts from):

```bash
$ echo -n SEED_PHRASE=12_WORD_MNEMONIC > .env
```

#### 1) Create externalAddresses.json in root directory.:

ChainID of Lisk Sepolia Testnet is 4202. Therefore, the externalAddresses.json need to have the sets of addresses having 4202 as key. For example, like below.

```JSON
{
  "4202": {
    "WNATIVE": "0x4200000000000000000000000000000000000006"
  }
}
```

The WNATIVE address above is officially deployed on the Lisk Sepolia Testnet network. Therefore, I recommend using this address unless you have already deployed or are willing to deploy a new WNATIVE address for your testing purposes.

#### 2) Compile contracts

```bash
$ npm run compile
```

make sure that the contracts compile before deployment

#### 3) Deploy with below command

```bash
$ npm run deploy-lisk-sepolia
```

#### 4) Check contract addresses in addresses.json file in root

After deployment, addresses.json gets updated with addresses of proxies.

### On Lisk Mainnet (chainID 1135)

#### 0) Create SEED_PHRASE environment variable (12 word phrase of the wallet that holds the EOA that you would like to deploy contracts from):

```bash
$ echo -n SEED_PHRASE=12_WORD_MNEMONIC > .env
```

#### 1) Create externalAddresses.json in root directory.:

ChainID of Lisk Mainnet is 1135. Therefore, the externalAddresses.json need to have the sets of addresses having 1135 as key. For example, like below.

```JSON
{
  "1135": {
    "WNATIVE": "0x4200000000000000000000000000000000000006"
  }
}
```

The WNATIVE address above is officially deployed on the Lisk Mainnet network. Therefore, I recommend using this address unless you have already deployed or are willing to deploy a new WNATIVE address for your testing purposes.

#### 2) Compile contracts

```bash
$ npm run compile
```

make sure that the contracts compile before deployment

#### 3) Deploy with below command

```bash
$ npm run deploy-lisk
```

#### 4) Check contract addresses in addresses.json file in root

After deployment, addresses.json gets updated with addresses of proxies.

# Gas Report

## How to measure gas consumption for protocol deployment

#### 0) Run the following command

```bash
$ REPORT_GAS="true npx hardhat test" npm run gas-report
```

# PriceFeed

## How to use SimplePriceFeed

The default configuration for deployment specifies that SimplePriceFeed acts as the price feed for NATIVE collateral. To alter the price of the collateral, you must first establish the price within SimplePriceFeed and then set the Loan-to-Value (LTV) discounted price in the protocol via the PriceOracle contract.

```Solidity=
//In SimplePriceFeed contract

function setPrice(uint256 _price) external onlyOwner {}

```

You can establish the collateral price using the setPrice function mentioned above. To set the price of NATIVE to 2 USD, call the setPrice function with an argument of 2\*10^18.

Once the price is set in SimplePriceFeed, it is necessary to input the LTV discounted price into the protocol. This can be accomplished by calling the function provided below.

```Solidity=
//In PriceOracle contract

    function setPrice(bytes32 _collateralPoolId) external override {}

```

The setPrice function of the PriceOracle should be called with an argument, which is the collateralPoolId. This is a padded bytes32 value converted from the string 'NATIVE'.

0x4e41544956452000000000000000000000000000000000000000000000000000

For example, if the price of NATIVE set by SimplePriceFeed is 1 USD and the Loan-to-Value (LTV) ratio is 70%, then the LTV discounted price would be 0.7 USD.

## How to change priceFeed for the protocol

Please call below function to change priceFeed for the protocol.

```Solidity=
In CollateralPoolConfig

    function setPriceFeed(bytes32 _poolId, address _priceFeed) external onlyOwner {
        require(_priceFeed != address(0), "CollateralPoolConfig/zero-price-feed");
        require(IPriceFeed(_priceFeed).poolId() == _poolId, "CollateralPoolConfig/wrong-price-feed-pool");
        require(IPriceFeed(_priceFeed).isPriceOk(), "CollateralPoolConfig/unhealthy-price-feed");

        IPriceFeed(_priceFeed).peekPrice();

        _collateralPools[_poolId].priceFeed = _priceFeed;
        emit LogSetPriceFeed(msg.sender, _poolId, _priceFeed);
    }
```

Line 5~6 verifies the solvency of the new priceFeed. New priceFeed must have poolId same as the poolId of the collateral that you are trying to change priceFeed of. And also, the new priceFeed should already have its fresh price existing in it.

### Simple way to initialize other priceFeeds and priceOracles

`CentralizedOraclePriceFeed`

can be initialized with task below

```
tasks/switch-price-feed.js
```

#### To run the script for the price feed, ensure that the build files remain unchanged since deployment.

The default is set as CentralizedOraclePriceFeed

### Please prepare setFathomPriceOracle.json file in the root. The file looks like below

```JSON=
{
  "51":
  {
    "PriceAggregator":"0x0000000000000000000000000000000000000000",
    "SubscriptionsRegistry":"0x0000000000000000000000000000000000000000",
    "CollateralSymbol":"CGO",
  },
  "31337":
  {
    "PriceAggregator":"0x0000000000000000000000000000000000000000",
    "SubscriptionsRegistry":"0x0000000000000000000000000000000000000000",
    "CollateralSymbol":"CGO",
  },
  "17000":
  {
    "PriceAggregator":"0x0000000000000000000000000000000000000000",
    "SubscriptionsRegistry":"0x0000000000000000000000000000000000000000",
    "CollateralSymbol":"CGO",
  }
}
```

#### Run the init script with below command

```bash
$ npx hardhat switch-price-feed
```
