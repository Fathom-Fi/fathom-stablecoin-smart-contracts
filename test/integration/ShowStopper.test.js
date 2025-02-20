const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

const { WeiPerRad, WeiPerRay, WeiPerWad } = require("../helper/unit");
const { createProxyWallets } = require("../helper/proxy-wallets");
const PositionHelper = require("../helper/positions");
const { getProxy } = require("../../common/proxies");
const pools = require("../../common/collateral");

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
  let WNATIVE;

  let AliceAddress;
  let BobAddress;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);

    const { allice, bob } = await getNamedAccounts();
    AliceAddress = allice;
    BobAddress = bob;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

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

    const _WNATIVE = await deployments.get("WNATIVE");
    WNATIVE = await ethers.getContractAt("WNATIVE", _WNATIVE.address);
    const _MockCollateralTokenAdapter = await deployments.get("MockCollateralTokenAdapter");
    MockCollateralTokenAdapter = await ethers.getContractAt("MockCollateralTokenAdapter", _MockCollateralTokenAdapter.address);

    const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");
    await proxyWalletRegistry.setDecentralizedMode(true);

    ({
      proxyWallets: [aliceProxyWallet, bobProxyWallet],
    } = await createProxyWallets([AliceAddress, BobAddress]));

    await collateralPoolConfig.setStabilityFeeRate(pools.NATIVE, WeiPerRay);
    await collateralPoolConfig.setStabilityFeeRate(pools.WNATIVE, WeiPerRay);

    await fathomStablecoin.connect(provider.getSigner(AliceAddress)).approve(stablecoinAdapter.address, WeiPerWad.mul(10000));
  });

  describe("#cage", () => {
    context("when doesn't grant showStopperRole for showStopper", () => {
      it("should be revert", async () => {
        await accessControlConfig.revokeRole(await accessControlConfig.SHOW_STOPPER_ROLE(), showStopper.address);
        await expect(showStopper.cage(WeekInSeconds)).to.be.revertedWith("!(ownerRole or showStopperRole)");
      });
    });
    context("when grant showStopperRole for all contract", () => {
      it("should be able to cage", async () => {
        await showStopper.cage(WeekInSeconds);

        expect(await bookKeeper.live()).to.be.equal(0);
        expect(await liquidationEngine.live()).to.be.equal(0);
        expect(await systemDebtEngine.live()).to.be.equal(0);
        expect(await priceOracle.live()).to.be.equal(0);
      });
    });
    context("when some contract was already caged", () => {
      it("should be able to cage", async () => {
        await systemDebtEngine.cage();
        await showStopper.cage(WeekInSeconds);

        expect(await bookKeeper.live()).to.be.equal(0);
        expect(await liquidationEngine.live()).to.be.equal(0);
        expect(await systemDebtEngine.live()).to.be.equal(0);
        expect(await priceOracle.live()).to.be.equal(0);
      });
    });
  });
  describe("#cage(collateralPoolId)", () => {
    context("deployer cage WNATIVE pool", () => {
      it("should be able to cage", async () => {
        // 1.
        //  a. open a new position
        //  b. lock WNATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));

        await showStopper.cage(WeekInSeconds);
        await showStopper.cagePool(pools.NATIVE);

        expect(await showStopper.cagePrice(pools.NATIVE)).to.be.equal(WeiPerRay);
        expect(await showStopper.totalDebtShare(pools.NATIVE)).to.be.equal(WeiPerWad.mul(5));
      });
    });
    context("bookKeeper was already caged", () => {
      it("should be able to cage", async () => {
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));

        await bookKeeper.cage();
        await showStopper.cage(WeekInSeconds);
        await showStopper.cagePool(pools.NATIVE);

        expect(await showStopper.cagePrice(pools.NATIVE)).to.be.equal(WeiPerRay);
        expect(await showStopper.totalDebtShare(pools.NATIVE)).to.be.equal(WeiPerWad.mul(5));
      });
    });
  });
  describe("#accumulateBadDebt, #redeemLockedCollateral", () => {
    context("when the caller is not the position owner", () => {
      it("should not be able to redeemLockedCollateral", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock WNATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        await showStopper.cage(WeekInSeconds);

        await showStopper.cagePool(pools.NATIVE);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress);

        // redeem lock collateral position #1
        await expect(PositionHelper.redeemLockedCollateral(bobProxyWallet, BobAddress, positionId)).to.be.revertedWith("owner not allowed");
      });
    });
    context("when the caller is the position owner", () => {
      it("should be able to redeemLockedCollateral", async () => {
        // alice's position #1
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        await PositionHelper.openNATIVEPositionAndDraw(bobProxyWallet, BobAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        await showStopper.cage(WeekInSeconds);

        await showStopper.cagePool(pools.NATIVE);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress);
        const position1 = await bookKeeper.positions(pools.NATIVE, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress2);
        const position2 = await bookKeeper.positions(pools.NATIVE, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // redeem lock collateral position #1
        await PositionHelper.redeemLockedCollateral(aliceProxyWallet, AliceAddress, positionId);

        expect((await bookKeeper.positions(pools.NATIVE, positionAddress)).lockedCollateral).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, aliceProxyWallet.address)).to.be.equal(WeiPerWad.mul(5));

        // redeem lock collateral position #2
        await PositionHelper.redeemLockedCollateral(bobProxyWallet, BobAddress, positionId2);

        expect((await bookKeeper.positions(pools.NATIVE, positionAddress2)).lockedCollateral).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, bobProxyWallet.address)).to.be.equal(WeiPerWad.mul(5));
        await collateralTokenAdapter.cage();

        // emergency withdraw position #1
        await PositionHelper.emergencyWithdraw(aliceProxyWallet, AliceAddress, collateralTokenAdapter.address);
        expect(await WNATIVE.balanceOf(AliceAddress)).to.be.equal(WeiPerWad.mul(5));
        // emergency withdraw position #2
        await PositionHelper.emergencyWithdraw(bobProxyWallet, BobAddress, collateralTokenAdapter.address);
        expect(await WNATIVE.balanceOf(AliceAddress)).to.be.equal(WeiPerWad.mul(5));
      });
    });
  });
  describe("#finalizeDebt, #finalizeCashPrice", () => {
    context("when finalizeDebt and finalizeCashPrice", () => {
      it("should be able to call", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock NATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        //  a. open a new position
        //  b. lock NATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(bobProxyWallet, BobAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        await showStopper.cage(WeekInSeconds);

        await showStopper.cagePool(pools.NATIVE);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress);
        const position1 = await bookKeeper.positions(pools.NATIVE, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress2);
        const position2 = await bookKeeper.positions(pools.NATIVE, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // finalize debt
        await time.increase(WeekInSeconds);
        await showStopper.finalizeDebt();
        // total debt
        expect(await showStopper.debt()).to.be.equal(WeiPerRad.mul(10));

        // finalize cash price
        await showStopper.finalizeCashPrice(pools.NATIVE);
        // badDebtAccumulator / totalDebt = 10000000000000000000000000000000000000000000000 / 10000000000000000000 = 1000000000000000000000000000
        expect(await showStopper.finalCashPrice(pools.NATIVE)).to.be.equal(WeiPerRay);
      });
    });
  });
  describe("#accumulateStablecoin, #redeemStablecoin", () => {
    context("when redeem stablecoin", () => {
      it("should be able to accumulateStablecoin, redeemStablecoin", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock NATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);

        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        //  a. open a new position
        //  b. lock NATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(bobProxyWallet, BobAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        await showStopper.cage(WeekInSeconds);

        await showStopper.cagePool(pools.NATIVE);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress);
        const position1 = await bookKeeper.positions(pools.NATIVE, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress2);
        const position2 = await bookKeeper.positions(pools.NATIVE, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // finalize debt
        await time.increase(WeekInSeconds);
        await showStopper.finalizeDebt();
        expect(await showStopper.debt()).to.be.equal(WeiPerRad.mul(10));

        // finalize cash price NATIVE
        await showStopper.finalizeCashPrice(pools.NATIVE);
        // badDebtAccumulator / totalDebt = 10000000000000000000000000000000000000000000000 / 10000000000000000000 = 1000000000000000000000000000
        expect(await showStopper.finalCashPrice(pools.NATIVE)).to.be.equal("1000000000000000000000000000");

        // accumulate stablecoin
        await stablecoinAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, WeiPerWad.mul(5), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        await bookKeeper.connect(provider.getSigner(AliceAddress)).addToWhitelist(showStopper.address);

        await showStopper.connect(provider.getSigner(AliceAddress)).accumulateStablecoin(WeiPerWad.mul(5));

        // redeem stablecoin
        //,
        await showStopper.connect(provider.getSigner(AliceAddress)).redeemStablecoin(pools.NATIVE, WeiPerWad.mul(5));
        expect(await bookKeeper.collateralToken(pools.NATIVE, AliceAddress)).to.be.equal("5000000000000000000");
      });
    });
    context("when redeem stablecoin with two col types", () => {
      it("should be able to accumulateStablecoin, redeemStablecoin", async () => {
        // alice's position #1
        //  a. open a new position
        //  b. lock NATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(aliceProxyWallet, AliceAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress = await positionManager.positions(positionId);

        // bob's position #2
        //  a. open a new position
        //  b. lock NATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDraw(bobProxyWallet, BobAddress, pools.NATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId2 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress2 = await positionManager.positions(positionId2);

        // alice's position #3
        //  a. open a new position
        //  b. lock WNATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDrawMock(aliceProxyWallet, AliceAddress, pools.WNATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId3 = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
        const positionAddress3 = await positionManager.positions(positionId3);

        // bob's position #4
        //  a. open a new position
        //  b. lock WNATIVE
        //  c. mint FXD
        await PositionHelper.openNATIVEPositionAndDrawMock(bobProxyWallet, BobAddress, pools.WNATIVE, WeiPerWad.mul(10), WeiPerWad.mul(5));
        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);
        const positionId4 = await positionManager.ownerLastPositionId(bobProxyWallet.address);
        const positionAddress4 = await positionManager.positions(positionId4);

        await showStopper.cage(WeekInSeconds);

        await showStopper.cagePool(pools.NATIVE);

        await showStopper.cagePool(pools.WNATIVE);

        // accumulate bad debt posiion #1
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress);
        const position1 = await bookKeeper.positions(pools.NATIVE, positionAddress);
        expect(position1.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position1.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(5));

        // accumulate bad debt posiion #2
        await showStopper.accumulateBadDebt(pools.NATIVE, positionAddress2);
        const position2 = await bookKeeper.positions(pools.NATIVE, positionAddress2);
        expect(position2.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position2.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.NATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(10));

        // accumulate bad debt posiion #3
        await showStopper.accumulateBadDebt(pools.WNATIVE, positionAddress3);
        const position3 = await bookKeeper.positions(pools.WNATIVE, positionAddress3);
        expect(position3.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position3.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.WNATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(5));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(15));

        // accumulate bad debt posiion #4
        await showStopper.accumulateBadDebt(pools.WNATIVE, positionAddress4);
        const position4 = await bookKeeper.positions(pools.WNATIVE, positionAddress4);
        expect(position4.lockedCollateral).to.be.equal(WeiPerWad.mul(5));
        expect(position4.debtShare).to.be.equal(0);
        expect(await bookKeeper.collateralToken(pools.WNATIVE, showStopper.address)).to.be.equal(WeiPerWad.mul(10));
        expect(await bookKeeper.systemBadDebt(systemDebtEngine.address)).to.be.equal(WeiPerRad.mul(20));

        // finalize debt
        await time.increase(WeekInSeconds);
        await showStopper.finalizeDebt();
        expect(await showStopper.debt()).to.be.equal(WeiPerRad.mul(20));

        // finalize cash price NATIVE
        await showStopper.finalizeCashPrice(pools.NATIVE);

        expect(await showStopper.finalCashPrice(pools.NATIVE)).to.be.equal("500000000000000000000000000");

        // finalize cash price WNATIVE
        await showStopper.finalizeCashPrice(pools.WNATIVE);

        expect(await showStopper.finalCashPrice(pools.WNATIVE)).to.be.equal("500000000000000000000000000");

        // accumulate stablecoin
        await stablecoinAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, WeiPerWad.mul(5), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        await bookKeeper.connect(provider.getSigner(AliceAddress)).addToWhitelist(showStopper.address);

        await showStopper.connect(provider.getSigner(AliceAddress)).accumulateStablecoin(WeiPerWad.mul(5));

        await showStopper.connect(provider.getSigner(AliceAddress)).redeemStablecoin(pools.NATIVE, WeiPerWad.mul(5));
        expect(await bookKeeper.collateralToken(pools.NATIVE, AliceAddress)).to.be.equal("2500000000000000000");

        await showStopper.connect(provider.getSigner(AliceAddress)).redeemStablecoin(pools.WNATIVE, WeiPerWad.mul(5));
        expect(await bookKeeper.collateralToken(pools.WNATIVE, AliceAddress)).to.be.equal("2500000000000000000");

        await collateralTokenAdapter.cage();
        await collateralTokenAdapter.connect(provider.getSigner(AliceAddress)).emergencyWithdraw(AliceAddress);
        expect(await WNATIVE.balanceOf(AliceAddress)).to.be.equal("2500000000000000000");
        await MockCollateralTokenAdapter.cage();
        await MockCollateralTokenAdapter.connect(provider.getSigner(AliceAddress)).emergencyWithdraw(AliceAddress);
        expect(await WNATIVE.balanceOf(AliceAddress)).to.be.equal("5000000000000000000");
      });
    });
  });
});
