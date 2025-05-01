const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { WeiPerRay, WeiPerWad } = require("../helper/unit");
const AssertHelpers = require("../helper/assert");
const { createProxyWallets } = require("../helper/proxy-wallets");
const PositionHelper = require("../helper/positions");
const { getProxy } = require("../../common/proxies");
const pools = require("../../common/collateral");

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

describe("Position Closure without collateral withdrawal", () => {
  // Proxy wallet
  let aliceProxyWallet;

  // Contract
  let positionManager;
  let bookKeeper;
  let simplePriceFeed;
  let fathomStablecoin;
  let governor;

  let reentrancyAttacker;
  let reentrancyAttacker2;
  let reEntrantProxyWallet;
  let reEntrantProxyWallet2;

  let DeployerAddress;
  let AliceAddress;
  let DevAddress;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);

    const { deployer, allice, dev } = await getNamedAccounts();
    DeployerAddress = deployer;
    AliceAddress = allice;
    DevAddress = dev;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);
    const SimplePriceFeed = await deployments.get("SimplePriceFeed");
    simplePriceFeed = await ethers.getContractAt("SimplePriceFeed", SimplePriceFeed.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    const stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
    positionManager = await getProxy(proxyFactory, "PositionManager");
    fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");

    let values = [0];
    let targets = [proxyWalletRegistry.address];
    let calldatas = [proxyWalletRegistry.interface.encodeFunctionData("setDecentralizedMode", [true])];
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
    // await proxyWalletRegistry.setDecentralizedMode(true);

    // ({
    //   proxyWallets: [aliceProxyWallet],
    // } = await createProxyWallets([AliceAddress]));

    await proxyWalletRegistry.build(AliceAddress);
    const proxyWalletAddress = await proxyWalletRegistry.proxies(AliceAddress);
    aliceProxyWallet = await ethers.getContractAt("ProxyWallet", proxyWalletAddress);

    const ReentrancyAttacker = await deployments.get("ReentrancyAttacker");
    reentrancyAttacker = await ethers.getContractAt("ReentrancyAttacker", ReentrancyAttacker.address);
    const ReentrancyAttacker2 = await deployments.get("ReentrancyAttacker2");
    reentrancyAttacker2 = await ethers.getContractAt("ReentrancyAttacker2", ReentrancyAttacker2.address);

    //making proxyWallet of reentrancyAttacker contract
    await proxyWalletRegistry.build(reentrancyAttacker.address);
    await proxyWalletRegistry.build(reentrancyAttacker2.address);

    reEntrantProxyWallet = await proxyWalletRegistry.proxies(reentrancyAttacker.address);
    reEntrantProxyWallet2 = await proxyWalletRegistry.proxies(reentrancyAttacker2.address);

    await reentrancyAttacker.setProxyWallet(reEntrantProxyWallet);
    await reentrancyAttacker2.setProxyWallet(reEntrantProxyWallet2);

    values = [0, 0];
    targets = [stabilityFeeCollector.address, simplePriceFeed.address];
    calldatas = [
      stabilityFeeCollector.interface.encodeFunctionData("setSystemDebtEngine", [DevAddress]),
      simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay]),
    ];
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
    // await stabilityFeeCollector.setSystemDebtEngine(DevAddress);
    await fathomStablecoin.connect(provider.getSigner(AliceAddress)).approve(aliceProxyWallet.address, WeiPerWad.mul(10000));
  });

  describe("#wipeAndUnlockXDC", () => {
    context("open position and pay back debt without collateral withdrawal", () => {
      it("should be success", async () => {
        // await simplePriceFeed.setPrice(WeiPerRay);

        // position 1
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));

        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        //  a. repay 2 WAD of FXD
        //  b. alice doesn't unlock any XDC
        //  c. check if the position has the same amount of lockedCollateral
        //  d. check if the position has now debtShare of 3 WAD (5-2)

        await PositionHelper.wipeAndUnlockXDC(aliceProxyWallet, AliceAddress, positionId, 0, WeiPerWad.mul(2));

        const [lockedCollateral, debtShare] = await bookKeeper.positions(pools.XDC, positionAddress);

        expect(lockedCollateral).to.be.equal(WeiPerWad.mul(10));
        AssertHelpers.assertAlmostEqual(debtShare, WeiPerWad.mul(3));
      });
    });
    context("try reentry with ReentrancyAttacker", () => {
      it("should not make change to the position", async () => {
        // await simplePriceFeed.setPrice(WeiPerRay);

        // position 1
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));

        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // call allowmanagerPosition so that reentrancyAttacker can close position
        await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, reEntrantProxyWallet, true);
        //transfer some FXD to reentrancyAttacker contract
        await fathomStablecoin.connect(provider.getSigner(AliceAddress)).transfer(reentrancyAttacker.address, WeiPerWad.mul(5));
        //reentrancyAttack approve reEntrantProxyWallet as spender of FXD
        await reentrancyAttacker.approveWallet(fathomStablecoin.address);
        //reentrancyAttacker tries to call wipeAndUnlockXDC and then all proxyWallet again with fallback function
        //but due to gas limit set in safeTransferETH, the fn call fails.

        PositionHelper.wipeAndUnlockXDC(reentrancyAttacker, AliceAddress, positionId, WeiPerWad.mul(1), WeiPerWad.mul(2));

        const [lockedCollateral, debtShare] = await bookKeeper.positions(pools.XDC, positionAddress);

        expect(lockedCollateral).to.be.equal(WeiPerWad.mul(10));
        AssertHelpers.assertAlmostEqual(debtShare, WeiPerWad.mul(5));
      });
    });
    context("try reentry with ReentrancyAttacker2", () => {
      it("should fail", async () => {
        // await simplePriceFeed.setPrice(WeiPerRay);

        // position 1
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));

        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // call allowmanagerPosition so that reentrancyAttacker can close position
        await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, reEntrantProxyWallet2, true);
        //transfer some FXD to reentrancyAttacker contract
        await fathomStablecoin.connect(provider.getSigner(AliceAddress)).transfer(reentrancyAttacker2.address, WeiPerWad.mul(5));
        //reentrancyAttack approve reEntrantProxyWallet as spender of FXD
        await reentrancyAttacker2.approveWallet(fathomStablecoin.address);
        //reentrancyAttacker tries to call wipeAndUnlockXDC and then all proxyWallet again with fallback function
        //but due to gas limit set in safeTransferETH, the fn call fails.

        await expect(
          PositionHelper.wipeAndUnlockXDC(reentrancyAttacker2, AliceAddress, positionId, WeiPerWad.mul(1), WeiPerWad.mul(2))
        ).to.be.revertedWith("!safeTransferETH");
      });
    });
  });

  describe("#wipeAllAndUnlockXDC", () => {
    context("open position and pay back debt without collateral withdrawal", () => {
      it("should be success", async () => {
        // await simplePriceFeed.setPrice(WeiPerRay);

        // position 1
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // position 2
        //  a. open a new position
        //  b. lock WXDC
        //  c. mint FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5));

        //  a. repay debt fully for position1
        //  b. alice doesn't unlock any XDC
        //  c. check if the position has the same amount of lockedCollateral
        //  d. check if the position has now debtShare of 0 WAD
        await PositionHelper.wipeAllAndUnlockXDC(aliceProxyWallet, AliceAddress, positionId, 0);

        const [lockedCollateral, debtShare] = await bookKeeper.positions(pools.XDC, positionAddress);

        expect(lockedCollateral).to.be.equal(WeiPerWad.mul(10));
        expect(debtShare).to.be.equal(0);
      });
    });
  });
});
