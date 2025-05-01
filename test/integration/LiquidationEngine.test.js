const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { BigNumber } = ethers;
const { parseEther, parseUnits, defaultAbiCoder, formatBytes32String } = ethers.utils;

const { WeiPerRay, WeiPerWad } = require("../helper/unit");
const AssertHelpers = require("../helper/assert");
const { createProxyWallets } = require("../helper/proxy-wallets");
const PositionHelper = require("../helper/positions");
const { getProxy } = require("../../common/proxies");
const pools = require("../../common/collateral");

const CLOSE_FACTOR_BPS = BigNumber.from(5000);
const LIQUIDATOR_INCENTIVE_BPS = BigNumber.from(10500);
const TREASURY_FEE_BPS = BigNumber.from(5000);
const COLLATERAL_POOL_ID = formatBytes32String("XDC");
const BPS = BigNumber.from(10000);

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

describe("LiquidationEngine", () => {
  // Contracts
  let aliceProxyWallet;
  let WXDC;
  let bookKeeper;
  let fathomToken;
  let positionManager;
  let stabilityFeeCollector;
  let liquidationEngine;
  let fixedSpreadLiquidationStrategy;
  let fathomStablecoin;
  let simplePriceFeed;
  let systemDebtEngine;
  let collateralPoolConfig;
  let priceOracle;
  let governor;

  let DeployerAddress;
  let AliceAddress;
  let BobAddress;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);

    const { deployer, allice, bob } = await getNamedAccounts();
    DeployerAddress = deployer;
    AliceAddress = allice;
    BobAddress = bob;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    const _WXDC = await deployments.get("WXDC");
    WXDC = await ethers.getContractAt("WXDC", _WXDC.address);

    collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");
    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    positionManager = await getProxy(proxyFactory, "PositionManager");
    stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
    fixedSpreadLiquidationStrategy = await getProxy(proxyFactory, "FixedSpreadLiquidationStrategy");
    const liquidationEngineAsAdmin = await getProxy(proxyFactory, "LiquidationEngine");
    systemDebtEngine = await getProxy(proxyFactory, "SystemDebtEngine");
    fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    priceOracle = await getProxy(proxyFactory, "PriceOracle");
    const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");

    const values = [0, 0, 0, 0, 0, 0, 0];
    const targets = [
      proxyWalletRegistry.address,
      collateralPoolConfig.address,
      collateralPoolConfig.address,
      collateralPoolConfig.address,
      collateralPoolConfig.address,
      collateralPoolConfig.address,
      liquidationEngineAsAdmin.address,
    ];

    const calldatas = [
      proxyWalletRegistry.interface.encodeFunctionData("setDecentralizedMode", [true]),
      collateralPoolConfig.interface.encodeFunctionData("setStabilityFeeRate", [pools.XDC, WeiPerRay]),
      collateralPoolConfig.interface.encodeFunctionData("setLiquidationRatio", [pools.XDC, WeiPerRay]),
      collateralPoolConfig.interface.encodeFunctionData("setLiquidatorIncentiveBps", [pools.XDC, LIQUIDATOR_INCENTIVE_BPS]),
      collateralPoolConfig.interface.encodeFunctionData("setCloseFactorBps", [pools.XDC, CLOSE_FACTOR_BPS]),
      collateralPoolConfig.interface.encodeFunctionData("setTreasuryFeesBps", [pools.XDC, TREASURY_FEE_BPS]),
      liquidationEngineAsAdmin.interface.encodeFunctionData("addToWhitelist", [BobAddress]),
    ];

    const proposalTx = await governor.propose(targets, values, calldatas, "Set LiquidationEngine");
    const proposalReceipt = await proposalTx.wait();
    const proposalId = proposalReceipt.events[0].args.proposalId;

     // wait for the voting period to pass
    await mine(VOTING_DELAY + 1); // wait for the voting period to pass

    await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

    
    await mine(VOTING_PERIOD + 1);

    // Queue the TX
    const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set LiquidationEngine"));
    await governor.queue(targets, values, calldatas, descriptionHash);

    await time.increase(MIN_DELAY + 1);
    await mine(1);

    // Execute
    await governor.execute(targets, values, calldatas, descriptionHash);

    liquidationEngine = await ethers.getContractAt("LiquidationEngine", liquidationEngineAsAdmin.address, provider.getSigner(BobAddress));

    const FathomToken = await deployments.get("FathomToken");
    fathomToken = await ethers.getContractAt("FathomToken", FathomToken.address);
    const SimplePriceFeed = await deployments.get("SimplePriceFeed");
    simplePriceFeed = await ethers.getContractAt("SimplePriceFeed", SimplePriceFeed.address);

    ({
      proxyWallets: [aliceProxyWallet],
    } = await createProxyWallets([AliceAddress, BobAddress]));

    await bookKeeper.connect(provider.getSigner(BobAddress)).whitelist(liquidationEngine.address);
    await bookKeeper.connect(provider.getSigner(BobAddress)).whitelist(fixedSpreadLiquidationStrategy.address);
  });

  describe("#liquidate", async () => {
    context("price drop but does not make the position underwater", async () => {
      it("should revert", async () => {
        // 1. Set price for XDC to 2 USD
        let values = [0, 0];
        let targets = [simplePriceFeed.address, priceOracle.address];
        let calldatas = [
          simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay.mul(2)]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
        ];

        let proposalTx = await governor.propose(targets, values, calldatas, "Set Price");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Price"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        // 2. Alice open a new position with 1 XDC and draw 1 FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, COLLATERAL_POOL_ID, WeiPerWad, WeiPerWad);
        const alicePositionAddress = await positionManager.positions(1);

        // // 3. XDC price drop to 1 USD
        calldatas = [
          simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
        ];
        proposalTx = await governor.propose(targets, values, calldatas, "Set Price New");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Price New"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        // 3.5 whitelist bob as liquidator
        // 4. Bob try to liquidate Alice's position but failed due to the price did not drop low enough
        await expect(
          liquidationEngine["liquidate(bytes32,address,uint256,uint256,address,bytes)"](
            COLLATERAL_POOL_ID,
            alicePositionAddress,
            1,
            1,
            AliceAddress,
            "0x"
          )
        ).to.be.revertedWith("LiquidationEngine/position-is-safe");
      });
    });

    context("safety buffer -0.1%, but liquidator does not have enough FXD to liquidate", async () => {
      it("should revert", async () => {
        // 1. Set priceWithSafetyMargin for XDC to 2 USD
        let values = [0, 0, 0];
        let targets = [simplePriceFeed.address, priceOracle.address, collateralPoolConfig.address];
        let calldatas = [
          simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay.mul(2)]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
          collateralPoolConfig.interface.encodeFunctionData("setLiquidationRatio", [COLLATERAL_POOL_ID, WeiPerRay]),
        ];

        let proposalTx = await governor.propose(targets, values, calldatas, "Set Price");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Price"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        // await simplePriceFeed.setPrice(WeiPerRay.mul(2));
        // await priceOracle.setPrice(COLLATERAL_POOL_ID);
        // await collateralPoolConfig.setLiquidationRatio(COLLATERAL_POOL_ID, WeiPerRay);

        // 2. Alice open a new position with 1 XDC and draw 1 FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, COLLATERAL_POOL_ID, WeiPerWad, WeiPerWad);
        const alicePositionAddress = await positionManager.positions(1);

        // 3. XDC price drop to 0.99 USD
        values = [0, 0];
        targets = [simplePriceFeed.address, priceOracle.address];
        calldatas = [
          simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay.sub(1).div(1e9)]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
        ];

        proposalTx = await governor.propose(targets, values, calldatas, "Set Price New");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Price New"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        // 4. Bob liquidate Alice's position up to full close factor successfully
        const debtShareToRepay = parseEther("0.5");
        await bookKeeper.whitelist(liquidationEngine.address);

        await expect(
          liquidationEngine["liquidate(bytes32,address,uint256,uint256,address,bytes)"](
            COLLATERAL_POOL_ID,
            alicePositionAddress,
            debtShareToRepay,
            ethers.constants.MaxUint256,
            BobAddress,
            defaultAbiCoder.encode(["address", "bytes"], [BobAddress, []])
          )
        ).to.be.reverted;
      });
    });

    context("main liquidation scenarios", async () => {
      const testParams = [
        {
          label: "safety buffer -0.18%, position is liquidated up to full close factor",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "285",
          debtShareToRepay: "1000",
          expectedDebtValueToRepay: "1000",
          expectedSeizedCollateral: "3.684210526315790000",
          expectedDebtShareAfterLiquidation: "1000",
          expectedSystemBadDebt: "0",
        },
        {
          label: "safety buffer -0.18%, position is liquidated up to some portion of close factor",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "285",
          debtShareToRepay: "200",
          expectedDebtValueToRepay: "200",
          expectedSeizedCollateral: "0.7368",
          expectedDebtShareAfterLiquidation: "1800",
          expectedSystemBadDebt: "0",
        },
        {
          label: "safety buffer -0.18%, position is liquidated exceeding close factor",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "285",
          debtShareToRepay: "2000",
          expectedDebtValueToRepay: "1000",
          expectedSeizedCollateral: "3.684210526315790000",
          expectedDebtShareAfterLiquidation: "1000",
          expectedSystemBadDebt: "0",
        },
        {
          label: "safety buffer -30%, position is liquidated up to full close factor, bad debt",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "200",
          debtShareToRepay: "1000",
          expectedDebtValueToRepay: "1904.761905",
          expectedSeizedCollateral: "10",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "95.238095",
        },
        {
          label: "safety buffer -30%, position is liquidated up to some portion of full close factor, bad debt",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "200",
          debtShareToRepay: "200",
          expectedDebtValueToRepay: "1904.761905",
          expectedSeizedCollateral: "10",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "95.238095",
        },
        {
          label: "safety buffer -10%, position collateral is fully liquidated because debt floor",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "1500",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "250",
          debtShareToRepay: "1000",
          expectedDebtValueToRepay: "2000",
          expectedSeizedCollateral: "8.4",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "0",
        },
        {
          label: "safety buffer -5.71% with 99% collateral factor, position is liquidated up to full close factor, bad debt",
          collateralAmount: "2000",
          collateralFactor: "0.99",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "1975",
          startingPrice: "1",
          nextPrice: "0.99",
          debtShareToRepay: "987.5",
          expectedDebtValueToRepay: "1885.714286",
          expectedSeizedCollateral: "2000",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "89.285714",
        },
        {
          label: "safety buffer -5.71% with 99% collateral factor, position collateral is fully liquidated because debt floor",
          collateralAmount: "2000",
          collateralFactor: "0.9",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "1800",
          startingPrice: "1",
          nextPrice: "0.99",
          debtShareToRepay: "900",
          expectedDebtValueToRepay: "900",
          expectedSeizedCollateral: "954.5455",
          expectedDebtShareAfterLiquidation: "900",
          expectedSystemBadDebt: "0",
        },
        {
          label: "safety buffer -7.83% with 99% collateral factor, position is liquidated up to full close factor, bad debt",
          collateralAmount: "2000",
          collateralFactor: "0.9",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "1800",
          startingPrice: "1",
          nextPrice: "0.92",
          debtShareToRepay: "900",
          expectedDebtValueToRepay: "1752.380952",
          expectedSeizedCollateral: "2000",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "47.619048",
        },
        {
          label: "safety buffer -8.90% with 99% collateral factor, position is liquidated up to full close factor, bad debt",
          collateralAmount: "2000",
          collateralFactor: "0.9",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "2500",
          debtFloor: "100",
          drawStablecoinAmount: "1800",
          startingPrice: "1",
          nextPrice: "0.91",
          debtShareToRepay: "450",
          expectedDebtValueToRepay: "1733.333333",
          expectedSeizedCollateral: "2000",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "66.666667",
        },
        {
          label: "safety buffer -0.91% with 99% collateral factor, position collateral is fully liquidated because debt floor",
          collateralAmount: "555.560",
          collateralFactor: "0.9",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "2500",
          debtFloor: "500",
          drawStablecoinAmount: "500",
          startingPrice: "1",
          nextPrice: "0.99",
          debtShareToRepay: "125",
          expectedDebtValueToRepay: "500",
          expectedSeizedCollateral: "530.3030303",
          expectedDebtShareAfterLiquidation: "0",
          expectedSystemBadDebt: "0",
        },
        {
          label: "safety buffer -0.91% with 99% collateral factor, position is liquidated up to full close factor",
          collateralAmount: "555.560",
          collateralFactor: "0.9",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "2500",
          debtFloor: "100",
          drawStablecoinAmount: "500",
          startingPrice: "1",
          nextPrice: "0.99",
          debtShareToRepay: "125",
          expectedDebtValueToRepay: "125",
          expectedSeizedCollateral: "132.5758",
          expectedDebtShareAfterLiquidation: "375.00",
          expectedSystemBadDebt: "0",
        },
      ];
      for (let i = 0; i < testParams.length; i++) {
        const testParam = testParams[i];
        it(testParam.label, async () => {
          let ratio = WeiPerRay.mul(1000).div(parseUnits(testParam.collateralFactor, 3));
          await fathomStablecoin.connect(provider.getSigner(BobAddress)).approve(fixedSpreadLiquidationStrategy.address, ethers.constants.MaxUint256);
          // 1. Set priceWithSafetyMargin for XDC to 2 USD
          let values = [0, 0, 0, 0, 0, 0, 0];
          let targets = [
            fathomStablecoin.address,
            collateralPoolConfig.address,
            collateralPoolConfig.address,
            simplePriceFeed.address,
            priceOracle.address,
            collateralPoolConfig.address,
            collateralPoolConfig.address,
          ];
          let calldatas = [
            fathomStablecoin.interface.encodeFunctionData("mint", [BobAddress, parseUnits(testParam.debtShareToRepay, 46)]),
            collateralPoolConfig.interface.encodeFunctionData("setLiquidatorIncentiveBps", [COLLATERAL_POOL_ID, testParam.liquidatorIncentiveBps]),
            collateralPoolConfig.interface.encodeFunctionData("setCloseFactorBps", [COLLATERAL_POOL_ID, testParam.closeFactorBps]),
            simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits(testParam.startingPrice, 18)]),
            priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
            collateralPoolConfig.interface.encodeFunctionData("setLiquidationRatio", [COLLATERAL_POOL_ID, ratio]),
            collateralPoolConfig.interface.encodeFunctionData("setDebtFloor", [COLLATERAL_POOL_ID, parseUnits(testParam.debtFloor, 45)]),
          ];

          let proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
          let proposalReceipt = await proposalTx.wait();
          let proposalId = proposalReceipt.events[0].args.proposalId;

           // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          
          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
          await governor.queue(targets, values, calldatas, descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          await governor.execute(targets, values, calldatas, descriptionHash);

          // 2. Alice open a new position with 1 XDC and draw 1 FXD
          const lockedCollateralAmount = parseEther(testParam.collateralAmount);
          const drawStablecoinAmount = parseEther(testParam.drawStablecoinAmount);

          await PositionHelper.openXDCPositionAndDraw(
            aliceProxyWallet,
            AliceAddress,
            COLLATERAL_POOL_ID,
            lockedCollateralAmount,
            drawStablecoinAmount
          );
          const alicePositionAddress = await positionManager.positions(1);
          const alicePosition = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);

          // 3. XDC price drop to 0.99 USD
          values = [0, 0];
          targets = [simplePriceFeed.address, priceOracle.address];
          calldatas = [
            simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits(testParam.nextPrice, 18)]),
            priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
          ];

          proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
          proposalReceipt = await proposalTx.wait();
          proposalId = proposalReceipt.events[0].args.proposalId;

           // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          
          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
          await governor.queue(targets, values, calldatas, descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          await governor.execute(targets, values, calldatas, descriptionHash);

          // 4. Bob liquidate Alice's position up to full close factor successfully
          const debtShareToRepay = parseEther(testParam.debtShareToRepay);
          const bobStablecoinBeforeLiquidation = await fathomStablecoin.balanceOf(BobAddress); //await bookKeeper.stablecoin(BobAddress)
          await liquidationEngine["liquidate(bytes32,address,uint256,uint256,address,bytes)"](
            COLLATERAL_POOL_ID,
            alicePositionAddress,
            debtShareToRepay,
            ethers.constants.MaxUint256,
            BobAddress,
            "0x"
          );
          const bobWETHAfterLiq = await WXDC.balanceOf(BobAddress);
          // 5. Settle system bad debt
          values = [0];
          targets = [systemDebtEngine.address];
          calldatas = [systemDebtEngine.interface.encodeFunctionData("settleSystemBadDebt", [await bookKeeper.stablecoin(systemDebtEngine.address)])];
          proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
          proposalReceipt = await proposalTx.wait();
          proposalId = proposalReceipt.events[0].args.proposalId;

           // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          
          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
          await governor.queue(targets, values, calldatas, descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          await governor.execute(targets, values, calldatas, descriptionHash);

          const bobStablecoinAfterLiquidation = await fathomStablecoin.balanceOf(BobAddress); //await bookKeeper.stablecoin(BobAddress)

          const alicePositionAfterLiquidation = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);
          const expectedSeizedCollateral = parseUnits(testParam.expectedSeizedCollateral, 18);
          const expectedLiquidatorIncentive = expectedSeizedCollateral.sub(expectedSeizedCollateral.mul(BPS).div(testParam.liquidatorIncentiveBps));
          const expectedTreasuryFee = expectedLiquidatorIncentive.mul(testParam.treasuryFeeBps).div(BPS);
          const expectedCollateralBobShouldReceive = expectedSeizedCollateral.sub(expectedTreasuryFee).div(WeiPerWad);

          AssertHelpers.assertAlmostEqual(
            alicePosition.lockedCollateral.sub(alicePositionAfterLiquidation.lockedCollateral).toString(),
            expectedSeizedCollateral.toString()
          );
          expect(alicePositionAfterLiquidation.debtShare).to.be.eq(parseUnits(testParam.expectedDebtShareAfterLiquidation, 18));
          AssertHelpers.assertAlmostEqual(
            (await bookKeeper.systemBadDebt(systemDebtEngine.address)).toString(),
            parseUnits(testParam.expectedSystemBadDebt, 45).toString()
          );
          AssertHelpers.assertAlmostEqual(bobWETHAfterLiq.div(WeiPerWad).toString(), expectedCollateralBobShouldReceive.toString());
          AssertHelpers.assertAlmostEqual(
            bobStablecoinBeforeLiquidation.sub(bobStablecoinAfterLiquidation).toString(),
            parseUnits(testParam.expectedDebtValueToRepay, 18).toString()
          );
          AssertHelpers.assertAlmostEqual(
            (await bookKeeper.collateralToken(COLLATERAL_POOL_ID, systemDebtEngine.address)).toString(),
            expectedTreasuryFee.toString()
          );
        });
      }
    });

    context("1st liquidation keep position unsafe, 2nd position fully liquidate the position", async () => {
      it("should success", async () => {
        const testParam = {
          label: "safety buffer -0.18%, position is liquidated up to full close factor",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "250",
          debtShareToRepay: "200",
          expectedDebtValueToRepay: "200",
          expectedSeizedCollateral: "0.84",
          expectedDebtShareAfterLiquidation: "1800",
          expectedSystemBadDebt: "0",
        };
        it(testParam.label, async () => {
          let ratio = WeiPerRay.mul(1000).div(parseUnits(testParam.collateralFactor, 3));
          let values = [0, 0, 0, 0, 0, 0];
          let targets = [
            collateralPoolConfig.address,
            collateralPoolConfig.address,
            simplePriceFeed.address,
            priceOracle.address,
            collateralPoolConfig.address,
            collateralPoolConfig.address,
          ];
          let calldatas = [
            collateralPoolConfig.interface.encodeFunctionData("setLiquidatorIncentiveBps", [COLLATERAL_POOL_ID, testParam.liquidatorIncentiveBps]),
            collateralPoolConfig.interface.encodeFunctionData("setCloseFactorBps", [COLLATERAL_POOL_ID, testParam.closeFactorBps]),
            simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits(testParam.startingPrice, 18)]),
            priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
            collateralPoolConfig.interface.encodeFunctionData("setLiquidationRatio", [COLLATERAL_POOL_ID, ratio]),
            collateralPoolConfig.interface.encodeFunctionData("setDebtFloor", [COLLATERAL_POOL_ID, parseUnits(testParam.debtFloor, 45)]),
          ];

          let proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
          let proposalReceipt = await proposalTx.wait();
          let proposalId = proposalReceipt.events[0].args.proposalId;

           // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          
          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
          await governor.queue(targets, values, calldatas, descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          await governor.execute(targets, values, calldatas, descriptionHash);

          // 2. Alice open a new position with 1 XDC and draw 1 FXD
          const lockedCollateralAmount = parseEther(testParam.collateralAmount);
          const drawStablecoinAmount = parseEther(testParam.drawStablecoinAmount);
          // await XDC.approve(aliceProxyWallet.address, lockedCollateralAmount, { from: AliceAddress })
          await PositionHelper.openXDCPositionAndDraw(
            aliceProxyWallet,
            AliceAddress,
            COLLATERAL_POOL_ID,
            lockedCollateralAmount,
            drawStablecoinAmount
          );
          const alicePositionAddress = await positionManager.positions(1);
          // const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
          const alicePosition = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);

          // 3. XDC price drop to 0.99 USD
          values = [0, 0];
          targets = [simplePriceFeed.address, priceOracle.address];
          calldatas = [
            simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits(testParam.nextPrice, 18)]),
            priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
          ];
          proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
          proposalReceipt = await proposalTx.wait();
          proposalId = proposalReceipt.events[0].args.proposalId;

           // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          
          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
          await governor.queue(targets, values, calldatas, descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          await governor.execute(targets, values, calldatas, descriptionHash);

          // 4. Bob liquidate Alice's position up to full close factor successfully
          const debtShareToRepay = parseEther(testParam.debtShareToRepay);
          const bobStablecoinBeforeLiquidation = await bookKeeper.stablecoin(BobAddress);
          await liquidationEngine["liquidate(bytes32,address,uint256,uint256,address,bytes)"](
            COLLATERAL_POOL_ID,
            alicePositionAddress,
            debtShareToRepay,
            ethers.constants.MaxUint256,
            BobAddress,
            "0x"
          );

          // 5. Settle system bad debt
          values = [0];
          targets = [systemDebtEngine.address];
          calldatas = [systemDebtEngine.interface.encodeFunctionData("settleSystemBadDebt", [await bookKeeper.stablecoin(systemDebtEngine.address)])];
          proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
          proposalReceipt = await proposalTx.wait();
          proposalId = proposalReceipt.events[0].args.proposalId;

           // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          
          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
          await governor.queue(targets, values, calldatas, descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          await governor.execute(targets, values, calldatas, descriptionHash);

          const bobStablecoinAfterLiquidation = await bookKeeper.stablecoin(BobAddress);

          const alicePositionAfterLiquidation = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);
          const expectedSeizedCollateral = parseUnits(testParam.expectedSeizedCollateral, 18);
          const expectedLiquidatorIncentive = expectedSeizedCollateral.sub(expectedSeizedCollateral.mul(BPS).div(testParam.liquidatorIncentiveBps));
          const expectedTreasuryFee = expectedLiquidatorIncentive.mul(testParam.treasuryFeeBps).div(BPS);

          AssertHelpers.assertAlmostEqual(
            alicePosition.lockedCollateral.sub(alicePositionAfterLiquidation.lockedCollateral).toString(),
            expectedSeizedCollateral.toString()
          );
          AssertHelpers.assertAlmostEqual(
            alicePosition.lockedCollateral.sub(alicePositionAfterLiquidation.lockedCollateral).toString(),
            expectedSeizedCollateral.toString()
          );
          expect(alicePositionAfterLiquidation.debtShare).to.be.eq(parseUnits(testParam.expectedDebtShareAfterLiquidation, 18));
          AssertHelpers.assertAlmostEqual(
            (await bookKeeper.systemBadDebt(systemDebtEngine.address)).toString(),
            parseUnits(testParam.expectedSystemBadDebt, 45).toString()
          );

          const expectedCollateralBobShouldReceive = expectedSeizedCollateral.sub(expectedTreasuryFee).div(WeiPerWad);
          AssertHelpers.assertAlmostEqual((await provider.getBalance(BobAddress)).toString(), expectedCollateralBobShouldReceive.toString());
          AssertHelpers.assertAlmostEqual(
            bobStablecoinBeforeLiquidation.sub(bobStablecoinAfterLiquidation).toString(),
            parseUnits(testParam.expectedDebtValueToRepay, 45).toString()
          );
          AssertHelpers.assertAlmostEqual(
            (await bookKeeper.collateralToken(COLLATERAL_POOL_ID, systemDebtEngine.address)).toString(),
            expectedTreasuryFee.toString()
          );
          expect(
            await fathomToken.balanceOf(aliceProxyWallet.address),
            "Alice's proxy wallet should have more than 0 FATHOM, because the liquidation process will distribute the pending FATHOM rewards to the position owner"
          ).to.not.equal(0);

          // Second Liquidation
          await liquidationEngine["liquidate(bytes32,address,uint256,uint256,address,bytes)"](
            COLLATERAL_POOL_ID,
            alicePositionAddress,
            ethers.constants.MaxUint256,
            ethers.constants.MaxUint256,
            BobAddress,
            "0x"
          );
          const alicePositionAfterLiquidation2 = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);
          expect(alicePositionAfterLiquidation2.lockedCollateral).to.be.eq(parseEther("4.62"));
          expect(alicePositionAfterLiquidation2.debtShare).to.be.eq(parseEther("900"));
        });
      });
    });

    context("safety buffer -20%, position is liquidated up to full close factor with some interest and debt floor", async () => {
      it("should success", async () => {
        let ratio = WeiPerRay.mul(1000).div(parseUnits("0.8", 3));
        // 0 whitelist bob as liquidator
        let values = [0, 0, 0, 0, 0];
        let targets = [
          fathomStablecoin.address,
          simplePriceFeed.address,
          priceOracle.address,
          collateralPoolConfig.address,
          collateralPoolConfig.address,
        ];
        let calldatas = [
          fathomStablecoin.interface.encodeFunctionData("mint", [BobAddress, parseUnits("3000", 45)]),
          simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits("367", 18)]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
          collateralPoolConfig.interface.encodeFunctionData("setLiquidationRatio", [COLLATERAL_POOL_ID, ratio]),
          collateralPoolConfig.interface.encodeFunctionData("setDebtFloor", [COLLATERAL_POOL_ID, parseEther("100").mul(WeiPerRay)]),
        ];
        let proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        /** await fathomStablecoin.mint(BobAddress, parseUnits("3000", 45)); */

        // 1. Set priceWithSafetyMargin for XDC to 420 USD
        /**await simplePriceFeed.setPrice(parseUnits("367", 18)); */
        /** await priceOracle.setPrice(COLLATERAL_POOL_ID); */

        /** await collateralPoolConfig.setLiquidationRatio(COLLATERAL_POOL_ID, ratio); */
        //   await collateralPoolConfig.setPriceWithSafetyMargin(COLLATERAL_POOL_ID, parseUnits("294", 27), { gasLimit: 1000000 })
        /** await collateralPoolConfig.setDebtFloor(COLLATERAL_POOL_ID, parseEther("100").mul(WeiPerRay)); */

        await fathomStablecoin.connect(provider.getSigner(BobAddress)).approve(fixedSpreadLiquidationStrategy.address, ethers.constants.MaxUint256);

        // 2. Alice open a new position with 10 XDC and draw 2000 FXD
        const lockedCollateralAmount = parseEther("10");
        const drawStablecoinAmount = parseEther("2000");

        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, COLLATERAL_POOL_ID, lockedCollateralAmount, drawStablecoinAmount);

        // Set stability fee rate to 0.5% APR
        values = [0];
        targets = [collateralPoolConfig.address];
        calldatas = [
          collateralPoolConfig.interface.encodeFunctionData("setStabilityFeeRate", [
            COLLATERAL_POOL_ID,
            BigNumber.from("1000000000158153903837946258"),
          ]),
        ];
        proposalTx = await governor.propose(targets, values, calldatas, "Set Stability Fee Rate");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Stability Fee Rate"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        /** await collateralPoolConfig.setStabilityFeeRate(COLLATERAL_POOL_ID, BigNumber.from("1000000000158153903837946258")); */

        const alicePositionAddress = await positionManager.positions(1);
        // const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
        const alicePosition = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);

        // 3. 1 year passed, XDC price drop to 285 USD
        await time.increase(31536000);
        await stabilityFeeCollector.collect(COLLATERAL_POOL_ID);
        const aliceDebtValueAfterOneYear = (await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress)).debtShare.mul(
          (await collateralPoolConfig.collateralPools(COLLATERAL_POOL_ID)).debtAccumulatedRate
        );
        AssertHelpers.assertAlmostEqual(aliceDebtValueAfterOneYear.toString(), parseEther("2010").mul(WeiPerRay).toString());
        values = [0, 0];
        targets = [simplePriceFeed.address, priceOracle.address];
        calldatas = [
          simplePriceFeed.interface.encodeFunctionData("setPrice", [parseEther("249.37")]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
        ];
        proposalTx = await governor.propose(targets, values, calldatas, "Set Price");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Price"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        /** await simplePriceFeed.setPrice(parseEther("249.37")); */
        /** await priceOracle.setPrice(COLLATERAL_POOL_ID); */

        // 4. Bob liquidate Alice's position up to full close factor successfully
        const debtShareToRepay = parseEther("1000");
        const bobStablecoinBeforeLiquidation = await fathomStablecoin.balanceOf(BobAddress);
        await liquidationEngine["liquidate(bytes32,address,uint256,uint256,address,bytes)"](
          COLLATERAL_POOL_ID,
          alicePositionAddress,
          debtShareToRepay,
          ethers.constants.MaxUint256,
          BobAddress,
          "0x"
        );
        const bobWETHAfterLiq = await WXDC.balanceOf(BobAddress);

        // // 5. Settle system bad debt
        values = [0];
        targets = [systemDebtEngine.address];
        calldatas = [
          systemDebtEngine.interface.encodeFunctionData("settleSystemBadDebt", [await bookKeeper.systemBadDebt(systemDebtEngine.address)]),
        ];
        proposalTx = await governor.propose(targets, values, calldatas, "Settle System Bad Debt");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Settle System Bad Debt"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        /** await systemDebtEngine.settleSystemBadDebt(await bookKeeper.systemBadDebt(systemDebtEngine.address)); */
        AssertHelpers.assertAlmostEqual(
          (await bookKeeper.stablecoin(systemDebtEngine.address)).toString(),
          parseEther("10").mul(WeiPerRay).toString()
        ); // There should be 10 FXD left in SystemDebtEngine collected from stability fee after `settleSystemBadDebt`

        const bobStablecoinAfterLiquidation = await fathomStablecoin.balanceOf(BobAddress);

        const alicePositionAfterLiquidation = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress);

        AssertHelpers.assertAlmostEqual(alicePositionAfterLiquidation.lockedCollateral.toString(), parseEther("5.768").toString());
        expect(alicePositionAfterLiquidation.debtShare, "debtShare should be 1000 FXD, because Bob liquidated 1000 FXD from Alice's position")
          .to.be.equal(alicePosition.debtShare.sub(debtShareToRepay))
          .to.be.equal(parseEther("1000"));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address), "System bad debt should be 0 FXD").to.be.equal(0);

        AssertHelpers.assertAlmostEqual(bobWETHAfterLiq.div(WeiPerWad).toString(), parseEther("4.1309099").div(WeiPerWad).toString());
        AssertHelpers.assertAlmostEqual(bobStablecoinBeforeLiquidation.sub(bobStablecoinAfterLiquidation).toString(), parseEther("1005").toString()); // Bob should pay 1005 FXD for this liquidation
        AssertHelpers.assertAlmostEqual(
          (await bookKeeper.collateralToken(COLLATERAL_POOL_ID, systemDebtEngine.address)).toString(),
          parseEther("0.1007539").toString()
        );
      });
    });

    context("batch liquidation", async () => {
      const testParams = [
        {
          label: "safety buffer -0.18%, position is liquidated up to full close factor",
          collateralAmount: "10",
          collateralFactor: "0.7",
          liquidatorIncentiveBps: "10500",
          treasuryFeeBps: "5000",
          closeFactorBps: "5000",
          debtFloor: "100",
          drawStablecoinAmount: "2000",
          startingPrice: "420",
          nextPrice: "285",
          debtShareToRepay: "1000",
          expectedDebtValueToRepay: "2000",
          expectedSeizedCollateral: "3.684210526315790000",
          expectedDebtShareAfterLiquidation: "1000",
          expectedSystemBadDebt: "0",
        },
      ];
      const testParam = testParams[0];
      it(testParam.label, async () => {
        let ratio = WeiPerRay.mul(1000).div(parseUnits(testParam.collateralFactor, 3));
        let values = [0, 0, 0, 0, 0, 0, 0];
        let targets = [
          fathomStablecoin.address,
          collateralPoolConfig.address,
          collateralPoolConfig.address,
          simplePriceFeed.address,
          priceOracle.address,
          collateralPoolConfig.address,
          collateralPoolConfig.address,
        ];
        let calldatas = [
          fathomStablecoin.interface.encodeFunctionData("mint", [BobAddress, parseUnits("2000", 46)]),
          collateralPoolConfig.interface.encodeFunctionData("setLiquidatorIncentiveBps", [COLLATERAL_POOL_ID, testParam.liquidatorIncentiveBps]),
          collateralPoolConfig.interface.encodeFunctionData("setCloseFactorBps", [COLLATERAL_POOL_ID, testParam.closeFactorBps]),
          simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits(testParam.startingPrice, 18)]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
          collateralPoolConfig.interface.encodeFunctionData("setLiquidationRatio", [COLLATERAL_POOL_ID, ratio]),
          collateralPoolConfig.interface.encodeFunctionData("setDebtFloor", [COLLATERAL_POOL_ID, parseUnits(testParam.debtFloor, 45)]),
        ];
        /** await fathomStablecoin.mint(BobAddress, parseUnits("2000", 46)); */
        await fathomStablecoin.connect(provider.getSigner(BobAddress)).approve(fixedSpreadLiquidationStrategy.address, ethers.constants.MaxUint256);
        let proposalTx = await governor.propose(targets, values, calldatas, "Set Protocol Config");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Protocol Config"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        /** await collateralPoolConfig.setLiquidatorIncentiveBps(COLLATERAL_POOL_ID, testParam.liquidatorIncentiveBps); */
        /** await collateralPoolConfig.setCloseFactorBps(COLLATERAL_POOL_ID, testParam.closeFactorBps); */
        /** await simplePriceFeed.setPrice(parseUnits(testParam.startingPrice, 18)); */
        /** await priceOracle.setPrice(COLLATERAL_POOL_ID); */

        /** await collateralPoolConfig.setLiquidationRatio(COLLATERAL_POOL_ID, ratio); */
        /** await collateralPoolConfig.setDebtFloor(COLLATERAL_POOL_ID, parseUnits(testParam.debtFloor, 45)); */

        // 2. Alice open a new position with 1 XDC and draw 1 FXD
        const lockedCollateralAmount = parseEther(testParam.collateralAmount);
        const drawStablecoinAmount = parseEther(testParam.drawStablecoinAmount);

        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, COLLATERAL_POOL_ID, lockedCollateralAmount, drawStablecoinAmount);
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, COLLATERAL_POOL_ID, lockedCollateralAmount, drawStablecoinAmount);

        const alicePositionAddress1 = await positionManager.positions(1);
        const alicePositionAddress2 = await positionManager.positions(2);
        const alicePosition = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress1);

        // 3. XDC price drop to 0.99 USD
        values = [0, 0];
        targets = [simplePriceFeed.address, priceOracle.address];
        calldatas = [
          simplePriceFeed.interface.encodeFunctionData("setPrice", [parseUnits(testParam.nextPrice, 18)]),
          priceOracle.interface.encodeFunctionData("setPrice", [COLLATERAL_POOL_ID]),
        ];
        proposalTx = await governor.propose(targets, values, calldatas, "Set Price");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Price"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        /** await simplePriceFeed.setPrice(parseUnits(testParam.nextPrice, 18)); */
        /** await priceOracle.setPrice(COLLATERAL_POOL_ID); */

        // 4. Bob liquidate Alice's position up to full close factor successfully
        const debtShareToRepay = parseEther(testParam.debtShareToRepay);
        const bobStablecoinBeforeLiquidation = await fathomStablecoin.balanceOf(BobAddress);

        await liquidationEngine.batchLiquidate(
          [COLLATERAL_POOL_ID, COLLATERAL_POOL_ID],
          [alicePositionAddress1, alicePositionAddress2],
          [debtShareToRepay, debtShareToRepay],
          [ethers.constants.MaxUint256, ethers.constants.MaxUint256],
          [BobAddress, BobAddress],
          ["0x", "0x"]
        );
        const bobWETHAfterLiq = await WXDC.balanceOf(BobAddress);

        // 5. Settle system bad debt
        values = [0];
        targets = [systemDebtEngine.address];
        calldatas = [systemDebtEngine.interface.encodeFunctionData("settleSystemBadDebt", [await bookKeeper.stablecoin(systemDebtEngine.address)])];
        proposalTx = await governor.propose(targets, values, calldatas, "Set System Debt Engine");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

         // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        
        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set System Debt Engine"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        /** await systemDebtEngine.settleSystemBadDebt(await bookKeeper.stablecoin(systemDebtEngine.address)); */

        const bobStablecoinAfterLiquidation = await fathomStablecoin.balanceOf(BobAddress);

        const alicePositionAfterLiquidation = await bookKeeper.positions(COLLATERAL_POOL_ID, alicePositionAddress1);
        const expectedSeizedCollateral = parseUnits(testParam.expectedSeizedCollateral, 18);
        const expectedLiquidatorIncentive = expectedSeizedCollateral.sub(expectedSeizedCollateral.mul(BPS).div(testParam.liquidatorIncentiveBps));
        const expectedTreasuryFee = expectedLiquidatorIncentive.mul(testParam.treasuryFeeBps).div(BPS);
        const expectedCollateralBobShouldReceive = expectedSeizedCollateral.sub(expectedTreasuryFee).mul(2);

        // TODO: check
        AssertHelpers.assertAlmostEqual(
          alicePosition.lockedCollateral.sub(alicePositionAfterLiquidation.lockedCollateral).toString(),
          expectedSeizedCollateral.toString()
        );

        expect(alicePositionAfterLiquidation.debtShare).to.be.eq(parseUnits(testParam.expectedDebtShareAfterLiquidation, 18));

        AssertHelpers.assertAlmostEqual(
          (await bookKeeper.systemBadDebt(systemDebtEngine.address)).toString(),
          parseUnits(testParam.expectedSystemBadDebt, 45).toString()
        );

        AssertHelpers.assertAlmostEqual(bobWETHAfterLiq.div(WeiPerWad).toString(), expectedCollateralBobShouldReceive.div(WeiPerWad).toString());

        AssertHelpers.assertAlmostEqual(
          bobStablecoinBeforeLiquidation.sub(bobStablecoinAfterLiquidation).toString(),
          parseUnits(testParam.expectedDebtValueToRepay, 18).toString()
        );

        AssertHelpers.assertAlmostEqual(
          (await bookKeeper.collateralToken(COLLATERAL_POOL_ID, systemDebtEngine.address)).toString(),
          expectedTreasuryFee.mul(2).toString()
        );
      });
    });
  });
});
