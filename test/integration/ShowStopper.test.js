const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { WeiPerRad, WeiPerRay, WeiPerWad } = require("../helper/unit");
const { createProxyWallets } = require("../helper/proxy-wallets");
const PositionHelper = require("../helper/positions");
const { getProxy } = require("../../common/proxies");
const pools = require("../../common/collateral");

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

const WeekInSeconds = 604800;

describe("ShowStopper", () => {
  // Proxy wallet
  let aliceProxyWallet;
  let bobProxyWallet;

  // Contract
  let positionManager;
  let showStopper;
  let bookKeeper;
  let liquidationEngine;
  let systemDebtEngine;
  let priceOracle;
  let stablecoinAdapter;
  let accessControlConfig;
  let collateralTokenAdapter;
  let MockCollateralTokenAdapter;
  let WXDC;
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

    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    liquidationEngine = await getProxy(proxyFactory, "LiquidationEngine");
    positionManager = await getProxy(proxyFactory, "PositionManager");
    stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
    const fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    systemDebtEngine = await getProxy(proxyFactory, "SystemDebtEngine");
    priceOracle = await getProxy(proxyFactory, "PriceOracle");
    showStopper = await getProxy(proxyFactory, "ShowStopper");
    accessControlConfig = await getProxy(proxyFactory, "AccessControlConfig");
    const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");
    collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");

    const _WXDC = await deployments.get("WXDC");
    WXDC = await ethers.getContractAt("WXDC", _WXDC.address);
    const _MockCollateralTokenAdapter = await deployments.get("MockCollateralTokenAdapter");
    MockCollateralTokenAdapter = await ethers.getContractAt("MockCollateralTokenAdapter", _MockCollateralTokenAdapter.address);

    const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");

    let values = [0, 0, 0];
    let targets = [proxyWalletRegistry.address, collateralPoolConfig.address, collateralPoolConfig.address];
    let calldatas = [
      proxyWalletRegistry.interface.encodeFunctionData("setDecentralizedMode", [true]),
      collateralPoolConfig.interface.encodeFunctionData("setStabilityFeeRate", [pools.XDC, WeiPerRay]),
      collateralPoolConfig.interface.encodeFunctionData("setStabilityFeeRate", [pools.WXDC, WeiPerRay]),
    ];
    const proposalTx = await governor.propose(targets, values, calldatas, "Set Config");
    const proposalReceipt = await proposalTx.wait();
    const proposalId = proposalReceipt.events[0].args.proposalId;

    // wait for the voting period to pass
    await mine(VOTING_DELAY + 1); // wait for the voting period to pass

    await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

    await mine(VOTING_PERIOD + 1);

    // Queue the TX
    const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Config"));
    await governor.queue(targets, values, calldatas, descriptionHash);

    await time.increase(MIN_DELAY + 1);
    await mine(1);

    // Execute
    await governor.execute(targets, values, calldatas, descriptionHash);
    // await proxyWalletRegistry.setDecentralizedMode(true);

    ({
      proxyWallets: [aliceProxyWallet, bobProxyWallet],
    } = await createProxyWallets([AliceAddress, BobAddress]));

    // await collateralPoolConfig.setStabilityFeeRate(pools.XDC, WeiPerRay);
    // await collateralPoolConfig.setStabilityFeeRate(pools.WXDC, WeiPerRay);

    await fathomStablecoin.connect(provider.getSigner(AliceAddress)).approve(stablecoinAdapter.address, WeiPerWad.mul(10000));
  });

  describe("#cage", () => {
    context("when doesn't grant showStopperRole for showStopper", () => {
      it("should be revert", async () => {
        const values = [0, 0];
        const targets = [accessControlConfig.address, showStopper.address];
        const calldatas = [
          accessControlConfig.interface.encodeFunctionData("revokeRole", [await accessControlConfig.SHOW_STOPPER_ROLE(), showStopper.address]),
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
        ];
        const proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await expect(governor.execute(targets, values, calldatas, descriptionHash)).to.be.revertedWith(
          "TimelockController: underlying transaction reverted"
        );
      });
    });
    context("when grant showStopperRole for all contract", () => {
      it("should be able to cage", async () => {
        const values = [0];
        const targets = [showStopper.address];
        const calldatas = [showStopper.interface.encodeFunctionData("cage", [WeekInSeconds])];
        const proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await showStopper.cage(WeekInSeconds);

        expect(await bookKeeper.live()).to.be.equal(0);
        expect(await liquidationEngine.live()).to.be.equal(0);
        expect(await systemDebtEngine.live()).to.be.equal(0);
        expect(await priceOracle.live()).to.be.equal(0);
      });
    });
    context("when some contract was already caged", () => {
      it("should be able to cage", async () => {
        const values = [0, 0];
        const targets = [systemDebtEngine.address, showStopper.address];
        const calldatas = [systemDebtEngine.interface.encodeFunctionData("cage"), showStopper.interface.encodeFunctionData("cage", [WeekInSeconds])];
        const proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await systemDebtEngine.cage();
        // await showStopper.cage(WeekInSeconds);

        expect(await bookKeeper.live()).to.be.equal(0);
        expect(await liquidationEngine.live()).to.be.equal(0);
        expect(await systemDebtEngine.live()).to.be.equal(0);
        expect(await priceOracle.live()).to.be.equal(0);
      });
    });
  });
  describe("#cage(collateralPoolId)", () => {
    context("deployer cage WXDC pool", () => {
      it("should be able to cage", async () => {
        // 1.
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));

        const values = [0, 0];
        const targets = [showStopper.address, showStopper.address];
        const calldatas = [
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
        ];
        const proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await showStopper.cage(WeekInSeconds);
        // await showStopper.cagePool(pools.XDC);

        expect(await showStopper.cagePrice(pools.XDC)).to.be.equal(WeiPerRay);
        expect(await showStopper.totalDebtShare(pools.XDC)).to.be.equal(WeiPerWad.mul(5));
      });
    });
    context("bookKeeper was already caged", () => {
      it("should be able to cage", async () => {
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));

        const values = [0, 0, 0];
        const targets = [bookKeeper.address, showStopper.address, showStopper.address];
        const calldatas = [
          bookKeeper.interface.encodeFunctionData("cage"),
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
        ];
        const proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await bookKeeper.cage();
        // await showStopper.cage(WeekInSeconds);
        // await showStopper.cagePool(pools.XDC);

        expect(await showStopper.cagePrice(pools.XDC)).to.be.equal(WeiPerRay);
        expect(await showStopper.totalDebtShare(pools.XDC)).to.be.equal(WeiPerWad.mul(5));
      });
    });
  });
  describe("#accumulateBadDebt, #redeemLockedCollateral", () => {
    context("when the caller is not the position owner", () => {
      it("should not be able to redeemLockedCollateral", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        const values = [0, 0];
        const targets = [showStopper.address, showStopper.address];
        const calldatas = [
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
        ];
        const proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await showStopper.cage(WeekInSeconds);

        // await showStopper.cagePool(pools.XDC);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress);

        // redeem lock collateral position #1
        await expect(PositionHelper.redeemLockedCollateral(bobProxyWallet, BobAddress, positionId)).to.be.revertedWith("owner not allowed");
      });
    });
    context("when the caller is the position owner", () => {
      it("should be able to redeemLockedCollateral", async () => {
        // alice's position #1
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        let values = [0, 0];
        let targets = [showStopper.address, showStopper.address];
        let calldatas = [
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
        ];
        let proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await showStopper.cage(WeekInSeconds);

        // await showStopper.cagePool(pools.XDC);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress);
        const position1 = await bookKeeper.positions(pools.XDC, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress2);
        const position2 = await bookKeeper.positions(pools.XDC, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // redeem lock collateral position #1
        await PositionHelper.redeemLockedCollateral(aliceProxyWallet, AliceAddress, positionId);

        expect((await bookKeeper.positions(pools.XDC, positionAddress)).lockedCollateral).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, aliceProxyWallet.address)).to.be.equal(WeiPerWad.mul(5));

        // redeem lock collateral position #2
        await PositionHelper.redeemLockedCollateral(bobProxyWallet, BobAddress, positionId2);

        expect((await bookKeeper.positions(pools.XDC, positionAddress2)).lockedCollateral).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, bobProxyWallet.address)).to.be.equal(WeiPerWad.mul(5));

        values = [0];
        targets = [collateralTokenAdapter.address];
        calldatas = [collateralTokenAdapter.interface.encodeFunctionData("cage")];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await collateralTokenAdapter.cage();

        // emergency withdraw position #1
        await PositionHelper.emergencyWithdraw(aliceProxyWallet, AliceAddress, collateralTokenAdapter.address);
        expect(await WXDC.balanceOf(AliceAddress)).to.be.equal(WeiPerWad.mul(5));
        // emergency withdraw position #2
        await PositionHelper.emergencyWithdraw(bobProxyWallet, BobAddress, collateralTokenAdapter.address);
        expect(await WXDC.balanceOf(AliceAddress)).to.be.equal(WeiPerWad.mul(5));
      });
    });
  });
  describe("#finalizeDebt, #finalizeCashPrice", () => {
    context("when finalizeDebt and finalizeCashPrice", () => {
      it("should be able to call", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock XDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        //  a. open a new position
        //  b. lock XDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        let values = [0, 0];
        let targets = [showStopper.address, showStopper.address];
        let calldatas = [
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
        ];
        let proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await showStopper.cage(WeekInSeconds);
        // await showStopper.cagePool(pools.XDC);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress);
        const position1 = await bookKeeper.positions(pools.XDC, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress2);
        const position2 = await bookKeeper.positions(pools.XDC, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // finalize debt
        await time.increase(WeekInSeconds);
        await showStopper.finalizeDebt();
        // total debt
        expect(await showStopper.debt()).to.be.equal(WeiPerRad.mul(10));

        // finalize cash price
        await showStopper.finalizeCashPrice(pools.XDC);
        // badDebtAccumulator / totalDebt = 10000000000000000000000000000000000000000000000 / 10000000000000000000 = 1000000000000000000000000000
        expect(await showStopper.finalCashPrice(pools.XDC)).to.be.equal(WeiPerRay);
      });
    });
  });
  describe("#accumulateStablecoin, #redeemStablecoin", () => {
    context("when redeem stablecoin", () => {
      it("should be able to accumulateStablecoin, redeemStablecoin", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock XDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);

        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        //  a. open a new position
        //  b. lock XDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        let values = [0, 0];
        let targets = [showStopper.address, showStopper.address];
        let calldatas = [
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
        ];
        let proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await showStopper.cage(WeekInSeconds);
        // await showStopper.cagePool(pools.XDC);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress);
        const position1 = await bookKeeper.positions(pools.XDC, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress2);
        const position2 = await bookKeeper.positions(pools.XDC, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // finalize debt
        await time.increase(WeekInSeconds);
        await showStopper.finalizeDebt();
        expect(await showStopper.debt()).to.be.equal(WeiPerRad.mul(10));

        // finalize cash price XDC
        await showStopper.finalizeCashPrice(pools.XDC);
        // badDebtAccumulator / totalDebt = 10000000000000000000000000000000000000000000000 / 10000000000000000000 = 1000000000000000000000000000
        expect(await showStopper.finalCashPrice(pools.XDC)).to.be.equal("1000000000000000000000000000");

        // accumulate stablecoin
        await stablecoinAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, WeiPerWad.mul(5), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        await bookKeeper.connect(provider.getSigner(AliceAddress)).whitelist(showStopper.address);

        await showStopper.connect(provider.getSigner(AliceAddress)).accumulateStablecoin(WeiPerWad.mul(5));

        // redeem stablecoin
        //,
        await showStopper.connect(provider.getSigner(AliceAddress)).redeemStablecoin(pools.XDC, WeiPerWad.mul(5));
        expect(await bookKeeper.collateralToken(pools.XDC, AliceAddress)).to.be.equal("5000000000000000000");
      });
    });
    context("when redeem stablecoin with two col types", () => {
      it("should be able to accumulateStablecoin, redeemStablecoin", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock XDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        //  a. open a new position
        //  b. lock XDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        // alice's position #3
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDrawMock(aliceProxyWallet, AliceAddress, pools.WXDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId3 = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress3 = await positionManager.positions(positionId3);

        // bob's position #4
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDrawMock(bobProxyWallet, BobAddress, pools.WXDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId4 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress4 = await positionManager.positions(positionId4);

        let values = [0, 0, 0];
        let targets = [showStopper.address, showStopper.address, showStopper.address];
        let calldatas = [
          showStopper.interface.encodeFunctionData("cage", [WeekInSeconds]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.XDC]),
          showStopper.interface.encodeFunctionData("cagePool", [pools.WXDC]),
        ];
        let proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);

        // await showStopper.cage(WeekInSeconds);
        // await showStopper.cagePool(pools.XDC);
        // await showStopper.cagePool(pools.WXDC);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress);
        const position1 = await bookKeeper.positions(pools.XDC, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.XDC, positionAddress2);
        const position2 = await bookKeeper.positions(pools.XDC, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.XDC, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // accumulate bad debt posiion #3
        await showStopper.accumulateBadDebt(pools.WXDC, positionAddress3);
        const position3 = await bookKeeper.positions(pools.WXDC, positionAddress3);
        expect(position3.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position3.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.WXDC, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(15));

        // accumulate bad debt posiion #4
        await showStopper.accumulateBadDebt(pools.WXDC, positionAddress4);
        const position4 = await bookKeeper.positions(pools.WXDC, positionAddress4);
        expect(position4.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position4.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.WXDC, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(20));

        // finalize debt
        await time.increase(WeekInSeconds);
        await showStopper.finalizeDebt();
        expect(await showStopper.debt()).to.be.equal(WeiPerRad.mul(20));

        // finalize cash price XDC
        await showStopper.finalizeCashPrice(pools.XDC);

        expect(await showStopper.finalCashPrice(pools.XDC)).to.be.equal("500000000000000000000000000");

        // finalize cash price WXDC
        await showStopper.finalizeCashPrice(pools.WXDC);

        expect(await showStopper.finalCashPrice(pools.WXDC)).to.be.equal("500000000000000000000000000");

        // accumulate stablecoin
        await stablecoinAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, WeiPerWad.mul(5), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        await bookKeeper.connect(provider.getSigner(AliceAddress)).whitelist(showStopper.address);

        await showStopper.connect(provider.getSigner(AliceAddress)).accumulateStablecoin(WeiPerWad.mul(5));

        await showStopper.connect(provider.getSigner(AliceAddress)).redeemStablecoin(pools.XDC, WeiPerWad.mul(5));
        expect(await bookKeeper.collateralToken(pools.XDC, AliceAddress)).to.be.equal("2500000000000000000");

        await showStopper.connect(provider.getSigner(AliceAddress)).redeemStablecoin(pools.WXDC, WeiPerWad.mul(5));
        expect(await bookKeeper.collateralToken(pools.WXDC, AliceAddress)).to.be.equal("2500000000000000000");

        values = [0, 0];
        targets = [collateralTokenAdapter.address, MockCollateralTokenAdapter.address];
        calldatas = [collateralTokenAdapter.interface.encodeFunctionData("cage"), MockCollateralTokenAdapter.interface.encodeFunctionData("cage")];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await collateralTokenAdapter.cage();

        await collateralTokenAdapter.connect(provider.getSigner(AliceAddress)).emergencyWithdraw(AliceAddress);
        expect(await WXDC.balanceOf(AliceAddress)).to.be.equal("2500000000000000000");

        // await MockCollateralTokenAdapter.cage();

        await MockCollateralTokenAdapter.connect(provider.getSigner(AliceAddress)).emergencyWithdraw(AliceAddress);
        expect(await WXDC.balanceOf(AliceAddress)).to.be.equal("5000000000000000000");
      });
    });
  });
});
