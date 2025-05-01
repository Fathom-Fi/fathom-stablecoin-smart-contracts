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

describe("PositionPermissions", () => {
  // Contracts
  let aliceProxyWallet;
  let bobProxyWallet;
  let collateralTokenAdapter;
  let stablecoinAdapter;
  let bookKeeper;
  let positionManager;
  let fathomStablecoin;
  let stabilityFeeCollector;
  let simplePriceFeed;
  let collateralTokenAdapter2;
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
    const SimplePriceFeed = await deployments.get("SimplePriceFeed");
    simplePriceFeed = await ethers.getContractAt("SimplePriceFeed", SimplePriceFeed.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    positionManager = await getProxy(proxyFactory, "PositionManager");
    stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
    fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
    const priceOracle = await getProxy(proxyFactory, "PriceOracle");
    collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
    const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");
    const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");
    let values = [0, 0, 0, 0];
    let targets = [
      proxyWalletRegistry.address,
      simplePriceFeed.address,
      collateralPoolConfig.address,
      collateralPoolConfig.address,
    ];
    let calldatas = [
      proxyWalletRegistry.interface.encodeFunctionData("setDecentralizedMode", [true]),
      simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay]),
      collateralPoolConfig.interface.encodeFunctionData("setStabilityFeeRate", [pools.XDC, WeiPerRay]),
      collateralPoolConfig.interface.encodeFunctionData("setStabilityFeeRate", [pools.GLD, WeiPerRay]),
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
    // await proxyWalletRegistry.setDecentralizedMode(true);

    const collateralTokenAdapter2Addr = await collateralPoolConfig.getAdapter(pools.GLD);
    collateralTokenAdapter2 = await ethers.getContractAt("CollateralTokenAdapter", collateralTokenAdapter2Addr);

    ({
      proxyWallets: [aliceProxyWallet, bobProxyWallet],
    } = await createProxyWallets([AliceAddress, BobAddress]));

    const gldAddr = await collateralTokenAdapter2.collateralToken();
    const GLD = await ethers.getContractAt("ERC20Mintable", gldAddr);

    await GLD.mint(AliceAddress, WeiPerWad.mul(1000));
    await GLD.connect(provider.getSigner(AliceAddress)).approve(aliceProxyWallet.address, WeiPerWad.mul(1000));
    await GLD.mint(BobAddress, WeiPerWad.mul(1000));
    await GLD.connect(provider.getSigner(BobAddress)).approve(bobProxyWallet.address, WeiPerWad.mul(1000));

    // await simplePriceFeed.setPrice(WeiPerRay);
    // await collateralPoolConfig.setStabilityFeeRate(pools.XDC, WeiPerRay);
    // await collateralPoolConfig.setStabilityFeeRate(pools.GLD, WeiPerRay);

    await priceOracle.setPrice(pools.GLD);
    await time.increase(900);
    await priceOracle.setPrice(pools.GLD);
    await priceOracle.setPrice(pools.XDC);
  });

  describe("#permissions", async () => {
    context("position owner is able to", async () => {
      context("lock collateral into their own position", async () => {
        it("should success", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);

          expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
          // 2. Alice try to adjust position, add 2 WXDC to position
          const posId = await positionManager.ownerLastPositionId(aliceProxyWallet.address);
          const own = await positionManager.owners(1);
          await PositionHelper.lockXDC(aliceProxyWallet, AliceAddress, 1, WeiPerWad.mul(2));
          const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 3 WXDC, because Alice locked 2 more WXDC").to.be.equal(
            WeiPerWad.mul(3)
          );
          expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
        });
      });

      context("move collateral", async () => {
        context("same collateral pool", async () => {
          context(
            "call openLockTokenAndDraw, unlock collateral and move the collateral from one position to another position within the same collateral pool",
            async () => {
              it("should success", async () => {
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                const alicePositionAddress = await positionManager.positions(1);
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
                // 2. Alice open a second new position with 2 WXDC and draw 1 FXD at same collateral pool
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                const alicePositionAddress2 = await positionManager.positions(2);
                const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition2 = await bookKeeper.positions(pools.XDC, alicePositionAddress2);
                expect(alicePosition2.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(
                  WeiPerWad.mul(2)
                );
                expect(alicePosition2.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance2, "Alice should receive 2 FXD from drawing FXD 2 times form 2 positions").to.be.equal(
                  WeiPerWad.mul(2)
                );
                // 3. Alice try to unlock 1 WXDC at second position
                await PositionHelper.adjustPosition(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  WeiPerWad.mul(-1),
                  0
                );
                const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress2);
                expect(
                  aliceAdjustPosition.lockedCollateral,
                  "Position #2's lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC from it"
                ).to.be.equal(WeiPerWad);
                expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                  "collateralToken inside Alice's Position#2 address should be 1 WXDC, because Alice unlocked 1 WXDC from the position"
                ).to.be.equal(WeiPerWad);
                // 4. Alice try to move collateral from second position to first position
                await PositionHelper.moveCollateral(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  alicePositionAddress,
                  WeiPerWad
                );
                const aliceMoveCollateral = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
                expect(
                  aliceMoveCollateral.lockedCollateral,
                  "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(aliceMoveCollateral.debtShare, "Alice's Position #1 debtShare should be 1 FXD, because Alice doesn't draw more").to.be.equal(
                  WeiPerWad
                );
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken inside Alice's Position #1 address should be 1 WXDC, because Alice moved 1 WXDC from Position #2 to Position #1."
                ).to.be.equal(WeiPerWad);
                expect(fathomStablecoinBalancefinal, "Alice should receive 2 FXD from drawing 2 FXD, because Alice draw 2 times").to.be.equal(
                  WeiPerWad.mul(2)
                );
              });
            }
          );
          context("open position, deposit collateral and move collateral from one position to another position", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Alice open a second new position at same collateral pool
              await PositionHelper.openPosition(aliceProxyWallet, AliceAddress, pools.XDC);
              const alicePositionAddress2 = await positionManager.positions(2);
              const alicePosition2 = await bookKeeper.positions(pools.XDC, alicePositionAddress2);
              expect(alicePosition2.lockedCollateral, "lockedCollateral should be 0 WXDC, because Alice doesn't locked WXDC").to.be.equal(0);
              expect(alicePosition2.debtShare, "debtShare should be 0 FXD, because doesn't drew FXD").to.be.equal(0);
              // 3. Alice deposit 3 WXDC to new position
              await PositionHelper.xdcAdapterDeposit(aliceProxyWallet, AliceAddress, await positionManager.positions(2), WeiPerWad.mul(3));
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                "collateralToken inside Alice's second position address should be 3 WXDC, because Alice deposit 3 WXDC into the second position"
              ).to.be.equal(WeiPerWad.mul(3));
              // 4. Alice try to move collateral from second position to first position
              await PositionHelper.moveCollateral(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                alicePositionAddress,
                WeiPerWad
              );
              const aliceMoveCollateral = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              expect(
                aliceMoveCollateral.lockedCollateral,
                "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
              ).to.be.equal(WeiPerWad);
              expect(aliceMoveCollateral.debtShare, "Alice's Position #1 debtShare should be 1 FXD, because Alice doesn't draw more").to.be.equal(
                WeiPerWad
              );
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's Position #1 address should be 1 WXDC, because Alice moved 1 WXDC from Position #2 to Position #1."
              ).to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                "collateralToken inside Alice's Position #2 address should be 2 WXDC, because Alice moved 1 WXDC to Position #1"
              ).to.be.equal(WeiPerWad.mul(2));
              expect(fathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice draw 1 time").to.be.equal(WeiPerWad);
            });
          });
          context("Alice open a position, lock collateral and move collateral to Bob's position", async () => {
            it("should success", async () => {
              // 1. Alice open position
              await PositionHelper.openPosition(aliceProxyWallet, AliceAddress, pools.XDC);
              const alicePositionAddress = await positionManager.positions(1);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 0 WXDC, because Alice doesn't locked WXDC").to.be.equal(0);
              expect(alicePosition.debtShare, "debtShare should be 0 FXD, because doesn't drew FXD").to.be.equal(0);
              // 2. Alice deposit 3 WXDC to new position
              await PositionHelper.xdcAdapterDeposit(aliceProxyWallet, AliceAddress, await positionManager.positions(1), WeiPerWad.mul(3));
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's second position address should be 3 WXDC, because Alice deposit 3 WXDC into the second position"
              ).to.be.equal(WeiPerWad.mul(3));
              // 3. Bob open a position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);

              const bobPositionAddress = await positionManager.positions(2);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 4. Alice try to move collateral to bob position
              await PositionHelper.moveCollateral(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                bobPositionAddress,
                WeiPerWad
              );
              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's Position address should be 2 WXDC, because Alice move 1 WXDC from Alice's Position to Bob's Position."
              ).to.be.equal(WeiPerWad.mul(2));
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's Position address should be 1 WXDC, because Alice moved 1 WXDC from Alice's Position to Bob's position"
              ).to.be.equal(WeiPerWad);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 0 FXD, because Alice doesn't draw").to.be.equal(0);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob draw 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
        context("between 2 collateral pool", async () => {
          context(
            "Alice opens 2 positions on 2 collateral pools (one position for each collateral pool) and Alice move collateral from one position to another position by calling openLockTokenAndDraw() twice",
            async () => {
              it("should success", async () => {
                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                const alicePositionAddress = await positionManager.positions(1);
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
                // 2. Alice open a second new position with 2 WXDC and draw 1 FXD at new collateral pool
                await PositionHelper.openPositionAndDraw(aliceProxyWallet, AliceAddress, pools.GLD, WeiPerWad.mul(2), WeiPerWad);

                const alicePositionAddress2 = await positionManager.positions(2);
                const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition2 = await bookKeeper.positions(pools.GLD, alicePositionAddress2);
                expect(alicePosition2.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(
                  WeiPerWad.mul(2)
                );
                expect(alicePosition2.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance2, "Alice should receive 2 FXD from drawing 1 FXD 2 times form 2 positions").to.be.equal(
                  WeiPerWad.mul(2)
                );
                // 3. Alice try to unlock 1 WXDC at second position
                await PositionHelper.adjustPosition(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  WeiPerWad.mul(-1),
                  0,
                  collateralTokenAdapter2.address
                );
                const aliceAdjustPosition = await bookKeeper.positions(pools.GLD, alicePositionAddress2);
                expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(
                  WeiPerWad
                );
                expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                ).to.be.equal(WeiPerWad);
                // 4. Alice try to move collateral from second position to first position
                await PositionHelper.moveCollateral(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  alicePositionAddress,
                  WeiPerWad,
                  collateralTokenAdapter2.address
                );
                const aliceMoveCollateral = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
                expect(
                  aliceMoveCollateral.lockedCollateral,
                  "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(aliceMoveCollateral.debtShare, "Alice's Position #1 debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(
                  WeiPerWad
                );
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken from Collateral Pool #1 inside Alice's Position #1 address should be 0 WXDC, because Alice can't move collateral from Position #2 to Position #1 as they are not from the same Collateral Pool."
                ).to.be.equal(0);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken from Collateral Pool #2 inside Alice's position #2 address should be 0 WXDC, because Alice moved 1 WXDC into Collateral Pool #2 inside Alice's position #1"
                ).to.be.equal(0);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress),
                  "collateralToken from Collateral Pool #2 inside Alice's position #1 address should be 1 WXDC, because Alice moved 1 WXDC form Alice's position #2 to Collateral Pool #2 inside Alice's position #1"
                ).to.be.equal(WeiPerWad);
                expect(fathomStablecoinBalancefinal, "Alice should receive 2 FXD from drawing 2 FXD, because Alice drew 2 times").to.be.equal(
                  WeiPerWad.mul(2)
                );
              });
            }
          );
          context(
            "Alice opens 2 positions on 2 collateral pools (one position for each collateral pool) and Alice move collateral from one position to another position",
            async () => {
              it("should success", async () => {
                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                const alicePositionAddress = await positionManager.positions(1);
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
                // 2. Alice open a second position at another collateral pool
                await PositionHelper.openPosition(aliceProxyWallet, AliceAddress, pools.GLD);

                const alicePositionAddress2 = await positionManager.positions(2);
                const alicePosition2 = await bookKeeper.positions(pools.GLD, alicePositionAddress2);
                expect(alicePosition2.lockedCollateral, "lockedCollateral should be 0 WXDC, because Alice doesn't locked WXDC").to.be.equal(0);
                expect(alicePosition2.debtShare, "debtShare should be 0 FXD, because doesn't drew FXD").to.be.equal(0);
                // 3. Alice deposit 3 WXDC to second position
                await PositionHelper.tokenAdapterDeposit(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.positions(2),
                  WeiPerWad.mul(3),
                  collateralTokenAdapter2.address
                );
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken inside Alice's second position address should be 3 WXDC, because Alice deposit 3 WXDC into the second position"
                ).to.be.equal(WeiPerWad.mul(3));
                // 4. Alice try to move collateral from second position to first position
                await PositionHelper.moveCollateral(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  alicePositionAddress,
                  WeiPerWad,
                  collateralTokenAdapter2.address
                );
                const aliceMoveCollateral = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
                expect(
                  aliceMoveCollateral.lockedCollateral,
                  "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(aliceMoveCollateral.debtShare, "Alice's Position #1 debtShare should be 1 FXD, because Alice doesn't draw more").to.be.equal(
                  WeiPerWad
                );
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken from Collateral Pool #1 inside Alice's Position #1 address should be 0 WXDC, because Alice can't move collateral from Position #2 to Position #1 as they are not from the same Collateral Pool."
                ).to.be.equal(0);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken from Collateral Pool #2 inside Alice's Position #2 address should be 2 WXDC, because Alice move 1 WXDC into Collateral Pool #2 inside Alice's position #1"
                ).to.be.equal(WeiPerWad.mul(2));
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress),
                  "collateralToken from Collateral Pool #2 inside Alice's Position #1 address should be 1 WXDC, because Alice move 1 WXDC form Alice's position #2 to Collateral Pool #2 inside Alice's position #1"
                ).to.be.equal(WeiPerWad);
                expect(fathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice draw 1 time").to.be.equal(WeiPerWad);
              });
            }
          );
          context(
            "Alice open a position, lock collateral and move collateral to Bob's position at another collateral pool by calling openLockTokenAndDraw() once and open() once",
            async () => {
              it("should success", async () => {
                // 1. Alice open position
                await PositionHelper.openPosition(aliceProxyWallet, AliceAddress, pools.XDC);
                const alicePositionAddress = await positionManager.positions(1);
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                expect(
                  alicePosition.lockedCollateral,
                  "Alice's Position #1 lockedCollateral should be 0 WXDC, because Alice didn't lock WXDC"
                ).to.be.equal(0);
                expect(alicePosition.debtShare, "Alice's Position #1 debtShare should be 0 FXD, because didn't draw FXD").to.be.equal(0);
                // 2. Alice deposit 3 WXDC to her position
                await PositionHelper.xdcAdapterDeposit(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.positions(1),
                  WeiPerWad.mul(3),
                  collateralTokenAdapter.address
                );
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken from Collateral Pool #1 inside Alice's Position #1 address should be 3 WXDC, because Alice deposit 3 WXDC into the her position"
                ).to.be.equal(WeiPerWad.mul(3));
                // 3. Bob open a position with 1 WXDC and draw 1 FXD at another collateral pool
                await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad, WeiPerWad);

                const bobPositionAddress = await positionManager.positions(2);
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
                const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
                expect(
                  bobPosition.lockedCollateral,
                  "lockedCollateral from Collateral Pool #2 inside Bob's Position #1 address should be 1 WXDC, because Bob locked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(
                  bobPosition.debtShare,
                  "debtShare from Collateral Pool #2 inside Bob's Position #1 address should be 1 FXD, because Bob drew 1 FXD"
                ).to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                  "collateralToken from Collateral Pool #2 inside Bob's Position #1 address should be 0 WXDC, because Bob locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
                // 4. Alice try to move collateral to Bob's position across collateral pool
                await PositionHelper.moveCollateral(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  bobPositionAddress,
                  WeiPerWad,
                  collateralTokenAdapter.address
                );
                const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
                const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken from Collateral Pool #1 inside Alice's Position #1 address should be 2 WXDC, because Alice move 1 WXDC to Bob's position"
                ).to.be.equal(WeiPerWad.mul(2));
                expect(
                  await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                  "collateralToken from Collateral Pool #1 inside new Bob's Position address should be 1 WXDC, because System auto create Bob's position at Collateral Pool #1, so Alice can move 1 WXDC into the new Bob's position"
                ).to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                  "collateralToken from Collateral Pool #2 inside Bob's Position #1 address should be 0 WXDC, because Alice can't move WXDC across collateral pool"
                ).to.be.equal(0);
                expect(aliceFathomStablecoinBalancefinal, "Alice should receive 0 FXD, because Alice didn't draw more").to.be.equal(0);
                expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
              });
            }
          );
        });
      });

      context("mint FXD", async () => {
        it("should success", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);

          expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

          // 2. Alice try to mint FXD
          await PositionHelper.draw(
            aliceProxyWallet,
            AliceAddress,
            pools.XDC,
            await positionManager.ownerLastPositionId(aliceProxyWallet.address),
            WeiPerWad
          );
          const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
          const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice doesn't add WXDC").to.be.equal(
            WeiPerWad.mul(2)
          );
          expect(aliceAdjustPosition.debtShare, "debtShare should be 2 FXD, because Alice drew more").to.be.equal(WeiPerWad.mul(2));
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance2, "Alice should receive 2 FXD from drawing 2 FXD").to.be.equal(WeiPerWad.mul(2));
        });
      });

      context("move position", async () => {
        context("same collateral pool", async () => {
          context(
            "call openLockTokenAndDraw, unlock collateral and move the collateral from one position to another position within the same collateral pool",
            async () => {
              it("should success", async () => {
                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                const alicePositionAddress = await positionManager.positions(1);
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);

                expect(
                  alicePosition.lockedCollateral,
                  "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "Alice's Position #1 collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

                // 2. Alice open a second new position with 2 WXDC and draw 1 FXD at same collateral pool
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                const alicePositionAddress2 = await positionManager.positions(2);
                const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition2 = await bookKeeper.positions(pools.XDC, alicePositionAddress2);

                expect(
                  alicePosition2.lockedCollateral,
                  "Alice's Position #2 lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                ).to.be.equal(WeiPerWad.mul(2));
                expect(alicePosition2.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                  "Alice's Position #2 collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance2, "Alice should receive 2 FXD, because Alice drew FXD 2 times form 2 positions").to.be.equal(
                  WeiPerWad.mul(2)
                );

                // 3. Alice try to unlock 1 WXDC at second position
                await PositionHelper.adjustPosition(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  WeiPerWad.mul(-1),
                  0
                );
                const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress2);
                expect(
                  aliceAdjustPosition.lockedCollateral,
                  "Alice's Position #2 lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(aliceAdjustPosition.debtShare, "Alice's Position #2 debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(
                  WeiPerWad
                );
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                  "Alice's Position #2 collateralToken should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                ).to.be.equal(WeiPerWad);

                // 4. Alice try to move position from second position to first position
                await PositionHelper.movePosition(aliceProxyWallet, AliceAddress, 2, 1);
                const alicemovePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
                expect(
                  alicemovePosition.lockedCollateral,
                  "Alice's Position #1 lockedCollateral should be 2 WXDC, because Alice move form Position #2 to Position #1"
                ).to.be.equal(WeiPerWad.mul(2));
                expect(
                  alicemovePosition.debtShare,
                  "Alice's Position #1 debtShare should be 2 FXD, because Alice move form Position #2 to Position #1"
                ).to.be.equal(WeiPerWad.mul(2));
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                  "collateralToken inside Alice's Position #2 address should still be 1 WXDC, because Alice moving position will not move collateral"
                ).to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken inside Alice's Position #1 address should still be 0 WXDC, because Alice moving position will not move collateral"
                ).to.be.equal(0);
                expect(fathomStablecoinBalancefinal, "Alice should receive 2 FXD from drawing 2 FXD, because Alice drew 2 times").to.be.equal(
                  WeiPerWad.mul(2)
                );
              });
            }
          );
        });
        context("between 2 collateral pool", async () => {
          context(
            "Alice opens 2 positions on 2 collateral pools (one position for each collateral pool) and Alice move collateral from one position to another position",
            async () => {
              it("should revert", async () => {
                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                const alicePositionAddress = await positionManager.positions(1);
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);

                expect(
                  alicePosition.lockedCollateral,
                  "Collateral Pool #1 inside Bob's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(
                  alicePosition.debtShare,
                  "Collateral Pool #1 inside Bob's Position #1 debtShare should be 1 FXD, because Alice drew 1 FXD"
                ).to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

                // 2. Alice open a second new position with 2 WXDC and draw 1 FXD at new collateral pool
                await PositionHelper.openPositionAndDraw(aliceProxyWallet, AliceAddress, pools.GLD, WeiPerWad.mul(2), WeiPerWad);
                const alicePositionAddress2 = await positionManager.positions(2);
                const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
                const alicePosition2 = await bookKeeper.positions(pools.GLD, alicePositionAddress2);

                expect(
                  alicePosition2.lockedCollateral,
                  "Collateral Pool #2 inside Bob's Position #2 lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                ).to.be.equal(WeiPerWad.mul(2));
                expect(
                  alicePosition2.debtShare,
                  "Collateral Pool #2 inside Bob's Position #2 debtShare should be 1 FXD, because Alice drew 1 FXD"
                ).to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0);
                expect(fathomStablecoinBalance2, "Alice should receive 2 FXD from drawing 1 FXD 2 times form 2 positions").to.be.equal(
                  WeiPerWad.mul(2)
                );

                // 3. Alice try to unlock 1 WXDC at second position
                await PositionHelper.adjustPosition(
                  aliceProxyWallet,
                  AliceAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  WeiPerWad.mul(-1),
                  0,
                  collateralTokenAdapter2.address
                );
                const aliceAdjustPosition = await bookKeeper.positions(pools.GLD, alicePositionAddress2);
                expect(
                  aliceAdjustPosition.lockedCollateral,
                  "Collateral Pool #2 inside Bob's Position #2 lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC"
                ).to.be.equal(WeiPerWad);
                expect(
                  aliceAdjustPosition.debtShare,
                  "Collateral Pool #2 inside Bob's Position #2 debtShare should be 1 FXD, because Alice didn't draw more"
                ).to.be.equal(WeiPerWad);
                expect(
                  await bookKeeper.collateralToken(pools.GLD, alicePositionAddress2),
                  "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                ).to.be.equal(WeiPerWad);

                // 4. Alice try to move collateral from second position to first position
                const movePositionAbi = ["function movePosition(address _manager, uint256 _source, uint256 _destination)"];
                const movePositionIFace = new ethers.utils.Interface(movePositionAbi);
                const movePosition = movePositionIFace.encodeFunctionData("movePosition", [positionManager.address, 2, 1]);
                await expect(aliceProxyWallet.connect(provider.getSigner(AliceAddress)).execute(movePosition)).to.be.revertedWith(
                  "!same collateral pool"
                );
              });
            }
          );
        });
      });
    });

    context("position owner allow other user to manage position with proxy wallet", async () => {
      context("lock collateral into their own position", async () => {
        it("should success", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
          // 2. Alice allow Bob to manage position
          await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
          expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);
          // 3. Bob try to adjust Alice's position, add 2 WXDC to position
          await PositionHelper.lockXDC(bobProxyWallet, BobAddress, 1, WeiPerWad.mul(2));

          const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 3 WXDC, because Bob add locked 2 WXDC").to.be.equal(
            WeiPerWad.mul(3)
          );
        });
      });
      context("move collateral", async () => {
        context("same collateral pool", async () => {
          context("and Bob move collateral of Alice to himself", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Alice try to unlock 1 WXDC at her position
              await PositionHelper.adjustPosition(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                WeiPerWad.mul(-1),
                0
              );
              const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice doesn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
              ).to.be.equal(WeiPerWad);
              // 4. Alice allow Bob to manage position
              await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
              expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);
              // 5. Bob try to move collateral to Alice position
              await PositionHelper.moveCollateral(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                bobPositionAddress,
                WeiPerWad
              );
              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC of Alice's position to his position"
              ).to.be.equal(0);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob move 1 WXDC of Alice's position to his position"
              ).to.be.equal(WeiPerWad);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
        context("between collateral pool", async () => {
          context("and Bob move collateral of Alice to himself", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position at collateral pool 2 with 1 WXDC and draw 1 FXD
              await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad, WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Alice try to unlock 1 WXDC at her position
              await PositionHelper.adjustPosition(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                WeiPerWad.mul(-1),
                0,
                collateralTokenAdapter.address
              );
              const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC at her position"
              ).to.be.equal(WeiPerWad);
              // 4. Alice allow Bob to manage position
              await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
              expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);
              // 5. Bob try to move collateral to Alice position
              await PositionHelper.moveCollateral(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                bobPositionAddress,
                WeiPerWad,
                collateralTokenAdapter.address
              );

              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC of Alice's position to himself"
              ).to.be.equal(0);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 1 WXDC, because Bob move 1 WXDC of Alice's position to himself"
              ).to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob move 1 WXDC of Alice's position to himself"
              ).to.be.equal(0);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
      });
      context("mint FXD", async () => {
        it("should success", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
          // 2. Alice allow Bob to manage position
          await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
          expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);
          // 3. Bob try to mint FXD at Alice position
          await PositionHelper.draw(
            bobProxyWallet,
            BobAddress,
            pools.XDC,
            await positionManager.ownerLastPositionId(aliceProxyWallet.address),
            WeiPerWad
          );
          const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
          const BobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
          const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice didn't add WXDC").to.be.equal(
            WeiPerWad.mul(2)
          );
          expect(aliceAdjustPosition.debtShare, "debtShare should be 2 FXD, because Alice drew more").to.be.equal(WeiPerWad.mul(2));
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance2, "Alice should receive 1 FXD from Alice drew 1 time").to.be.equal(WeiPerWad);
          expect(BobFathomStablecoinBalance, "Bob should receive 1 FXD from mint FXD at Alice position").to.be.equal(WeiPerWad);
        });
      });
      context("move position", async () => {
        context("same collateral pool", async () => {
          it("should success", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(
              alicePosition.lockedCollateral,
              "Collateral Pool #1 inside Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
            ).to.be.equal(WeiPerWad);
            expect(
              alicePosition.debtShare,
              "Collateral Pool #1 inside Alice's Position #1 debtShare should be 1 FXD, because Alice drew 1 FXD"
            ).to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
            expect(
              bobPosition.lockedCollateral,
              "Collateral Pool #1 inside Bob's Position #1 lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
            ).to.be.equal(WeiPerWad);
            expect(
              bobPosition.debtShare,
              "Collateral Pool #1 inside Bob's Position #1 debtShare should be 1 FXD, because Bob drew 1 FXD"
            ).to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 3. Alice allow Bob to manage position
            await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
            expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);
            // 4. Bob try to move collateral to alice position
            await PositionHelper.movePosition(bobProxyWallet, BobAddress, 2, 1);
            const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
            const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
            const alicePositionAfterMovePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(
              alicePositionAfterMovePosition.lockedCollateral,
              "Collateral Pool #1 inside Alice's Position #1 lockedCollateral should be 2 WXDC, because Bob move locked 1 WXDC to Alice"
            ).to.be.equal(WeiPerWad.mul(2));
            expect(
              alicePositionAfterMovePosition.debtShare,
              "Collateral Pool #1 inside Alice's Position #1 debtShare should be 1 FXD, because Bob move DebtShare to Alice"
            ).to.be.equal(WeiPerWad.mul(2));
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice all lock collateral"
            ).to.be.equal(0);
            expect(
              await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob all lock collateral"
            ).to.be.equal(0);
            expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
            expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
          });
        });
        context("between 2 collateral pool", async () => {
          it("should revert", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(
              alicePosition.lockedCollateral,
              "Collateral Pool #1 inside Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
            ).to.be.equal(WeiPerWad);
            expect(
              alicePosition.debtShare,
              "Collateral Pool #1 inside Bob's Position #1 debtShare should be 1 FXD, because Alice drew 1 FXD"
            ).to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD at collateral pool id 2
            await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
            expect(
              bobPosition.lockedCollateral,
              "Collateral Pool #1 inside Bob's Position #1 lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
            ).to.be.equal(WeiPerWad);
            expect(
              bobPosition.debtShare,
              "Collateral Pool #1 inside Bob's Position #1 debtShare should be 1 FXD, because Bob drew 1 FXD"
            ).to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 3. Alice allow Bob to manage position
            await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
            expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);
            // 4. Bob try to move position to Alice position
            const movePositionAbi = ["function movePosition(address _manager, uint256 _source, uint256 _destination)"];
            const movePositionIFace = new ethers.utils.Interface(movePositionAbi);
            const movePositionCall = movePositionIFace.encodeFunctionData("movePosition", [positionManager.address, 2, 1]);
            await expect(bobProxyWallet.connect(provider.getSigner(BobAddress)).execute(movePositionCall)).to.be.revertedWith(
              "!same collateral pool"
            );
          });
        });
      });
    });

    context("position owner not allow other user to manage position with proxy wallet", async () => {
      context("lock collateral into their own position", async () => {
        it("should revert", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

          // 2. Bob try to adjust Alice's position, add 2 WXDC to position
          const lockAbi = ["function lockXDC(address _manager, address _xdcAdapter, uint256 _positionId, bytes calldata _data)"];
          let lockIFace = new ethers.utils.Interface(lockAbi);
          const lockTokenCall = lockIFace.encodeFunctionData("lockXDC", [
            positionManager.address,
            collateralTokenAdapter.address,
            await positionManager.ownerLastPositionId(aliceProxyWallet.address),
            ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]),
          ]);

          await expect(bobProxyWallet.connect(provider.getSigner(BobAddress)).execute(lockTokenCall, { value: WeiPerWad })).to.be.revertedWith(
            "owner not allowed"
          );
        });
      });
      context("move collateral", async () => {
        context("same collateral pool", async () => {
          context("and Bob move collateral to Alice", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Bob locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Bob try to unlock 1 WXDC at second position
              await PositionHelper.adjustPosition(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(bobProxyWallet.address),
                WeiPerWad.mul(-1),
                0
              );
              const bobAdjustPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
              expect(bobAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobAdjustPosition.debtShare, "debtShare should be 1 FXD, because Bob doesn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 1 WXDC, because Bob unlocked 1 WXDC into the position"
              ).to.be.equal(WeiPerWad);
              // 4. Bob try to move collateral to Alice position
              await PositionHelper.moveCollateral(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(bobProxyWallet.address),
                alicePositionAddress,
                WeiPerWad
              );
              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Bob move 1 WXDC to Alice's position"
              ).to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob move 1 WXDC to Alice's position"
              ).to.be.equal(0);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
        context("between collateral pool", async () => {
          context("and Bob move collateral to Alice", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position at collateral pool 2 with 2 WXDC and draw 1 FXD
              await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad.mul(2), WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Bob locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Bob try to unlock 1 WXDC at second position
              await PositionHelper.adjustPosition(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(bobProxyWallet.address),
                WeiPerWad.mul(-1),
                0,
                collateralTokenAdapter2.address
              );
              const bobAdjustPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
              expect(bobAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobAdjustPosition.debtShare, "debtShare should be 1 FXD, because Bob didn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 1 WXDC, because Bob unlocked 1 WXDC into the position"
              ).to.be.equal(WeiPerWad);
              // 4. Bob try to move collateral to Alice position
              await PositionHelper.moveCollateral(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(bobProxyWallet.address),
                alicePositionAddress,
                WeiPerWad,
                collateralTokenAdapter2.address
              );
              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC to Alice's position"
              ).to.be.equal(0);
              expect(
                await bookKeeper.collateralToken(pools.GLD, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Bob move 1 WXDC to Alice's position"
              ).to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob move 1 WXDC to Alice's position"
              ).to.be.equal(0);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
      });
      context("mint FXD", async () => {
        it("should revert", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
          // 2. Bob try to mint FXD at Alice position
          let drawTokenAbi = [
            "function draw(address _manager, address _stabilityFeeCollector, address _stablecoinAdapter, uint256 _positionId, uint256 _amount, bytes calldata _data)",
          ];
          let drawTokenIFace = new ethers.utils.Interface(drawTokenAbi);
          let drawTokenCall = drawTokenIFace.encodeFunctionData("draw", [
            positionManager.address,
            stabilityFeeCollector.address,
            stablecoinAdapter.address,
            await positionManager.ownerLastPositionId(aliceProxyWallet.address),
            WeiPerWad,
            ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]),
          ]);
          await expect(bobProxyWallet.connect(provider.getSigner(BobAddress)).execute(drawTokenCall)).to.be.revertedWith("owner not allowed");
        });
      });
      context("move position", async () => {
        context("same collateral pool", async () => {
          it("should revert", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
            expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 3. Bob try to move collateral to alice position
            const movePositionAbi = ["function movePosition(address _manager, uint256 _source, uint256 _destination)"];
            const movePositionIFace = new ethers.utils.Interface(movePositionAbi);
            const movePositionCall = movePositionIFace.encodeFunctionData("movePosition", [positionManager.address, 2, 1]);
            await expect(bobProxyWallet.connect(provider.getSigner(BobAddress)).execute(movePositionCall)).to.be.revertedWith("owner not allowed");
          });
        });
        context("between 2 collateral pool", async () => {
          it("should revert", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

            // 2. Bob open a position with 1 WXDC and draw 1 FXD at collateral pool id 2
            await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
            expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

            // 3. Bob try to move position to Alice position
            const movePositionAbi = ["function movePosition(address _manager, uint256 _source, uint256 _destination)"];
            const movePositionIFace = new ethers.utils.Interface(movePositionAbi);
            const movePositionCall = movePositionIFace.encodeFunctionData("movePosition", [positionManager.address, 2, 1]);
            await expect(bobProxyWallet.connect(provider.getSigner(BobAddress)).execute(movePositionCall)).to.be.revertedWith("owner not allowed");
          });
        });
      });
    });

    context("position owner allow other user to manage position with user wallet address", async () => {
      context("move collateral", async () => {
        context("same collateral pool", async () => {
          context("and Bob move collateral of Alice to himself", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Alice try to unlock 1 WXDC at her position
              await PositionHelper.adjustPosition(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                WeiPerWad.mul(-1),
                0
              );
              const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
              ).to.be.equal(WeiPerWad);

              // 4. Alice allow Bob to manage position
              await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
              expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);

              // 5. Bob try to move collateral of Alice position to Bob position
              //   await positionManager["moveCollateral(uint256,address,uint256,address,bytes)"](
              await PositionHelper.moveCollateral(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                bobPositionAddress,
                WeiPerWad
              );

              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC to his position"
              ).to.be.equal(0);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Bob move 1 WXDC to his position"
              ).to.be.equal(WeiPerWad);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
        context("between collateral pool", async () => {
          context("and Bob move collateral of Alice to himself", async () => {
            it("should success", async () => {
              // 1. Alice open a new position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position at collateral pool 2 with 2 WXDC and draw 1 FXD
              await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad.mul(2), WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Bob locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Alice try to unlock 1 WXDC at her position
              await PositionHelper.adjustPosition(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                WeiPerWad.mul(-1),
                0,
                collateralTokenAdapter.address
              );
              const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC"
              ).to.be.equal(WeiPerWad);

              // 4. Alice allow Bob to manage her position
              await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, true);
              expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(true);

              // 5. Bob try to move collateral of Alice position to his position
              await PositionHelper.moveCollateral(
                bobProxyWallet,
                BobAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                bobPositionAddress,
                WeiPerWad,
                collateralTokenAdapter.address,
                AliceAddress
              );
              const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
              const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC to his position"
              ).to.be.equal(0);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 1 WXDC at collater pool 1, because Bob move 1 WXDC to his position"
              ).to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC at collater pool 2, because Bob move 1 WXDC to his position at collateral pool 1"
              ).to.be.equal(0);
              expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
              expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
            });
          });
        });
      });
      context("mint FXD", async () => {
        it("should success", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
          // 2. Alice allow Bob to manage position
          await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, BobAddress, true);
          expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, BobAddress)).to.be.equal(true);
          // 3. Bob try to mint FXD at Alice position

          await positionManager
            .connect(provider.getSigner(BobAddress))
            .adjustPosition(
              await positionManager.ownerLastPositionId(aliceProxyWallet.address),
              0,
              alicePosition.debtShare,
              ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress])
            );

          // 4. move stablecoin of alice to bob
          await positionManager
            .connect(provider.getSigner(BobAddress))
            .moveStablecoin(await positionManager.ownerLastPositionId(aliceProxyWallet.address), BobAddress, WeiPerRad);

          // 5. allow bob to window
          await bookKeeper.connect(provider.getSigner(BobAddress)).whitelist(stablecoinAdapter.address);

          // 6. mint FXD
          await stablecoinAdapter
            .connect(provider.getSigner(BobAddress))
            .withdraw(BobAddress, WeiPerWad, ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));
          const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress);
          const BobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
          const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice doesn't add WXDC").to.be.equal(
            WeiPerWad.mul(2)
          );
          expect(aliceAdjustPosition.debtShare, "debtShare should be 2 FXD, because Alice drew more").to.be.equal(WeiPerWad.mul(2));
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance2, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
          expect(BobFathomStablecoinBalance, "Bob should receive 1 FXD from Alice position").to.be.equal(WeiPerWad);
        });
      });
      context("move position", async () => {
        context("same collateral pool", async () => {
          it("should success", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
            expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 3. Alice allow Bob to manage position
            await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, BobAddress, true);
            expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, BobAddress)).to.be.equal(true);

            // 4. bob proxy wallet allow Bob address to manage position
            await PositionHelper.allowManagePosition(bobProxyWallet, BobAddress, 2, BobAddress, true);
            expect(await positionManager.ownerWhitelist(bobProxyWallet.address, 2, BobAddress)).to.be.equal(true);

            // 5. Bob try to move collateral to alice position
            await positionManager.connect(provider.getSigner(BobAddress)).movePosition(2, 1);
            const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress);
            const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress);
            const alicePositionAfterMovePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(
              alicePositionAfterMovePosition.lockedCollateral,
              "lockedCollateral should be 2 WXDC, because Bob move locked 1 WXDC to Alice"
            ).to.be.equal(WeiPerWad.mul(2));
            expect(alicePositionAfterMovePosition.debtShare, "debtShare should be 1 FXD, because Bob move DebtShare to Alice").to.be.equal(
              WeiPerWad.mul(2)
            );
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice all lock collateral"
            ).to.be.equal(0);
            expect(
              await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob all lock collateral"
            ).to.be.equal(0);
            expect(aliceFathomStablecoinBalancefinal, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(WeiPerWad);
            expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(WeiPerWad);
          });
        });
        context("between 2 collateral pool", async () => {
          it("should revert", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD at collateral pool id 2
            await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
            expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

            // 3. Alice allow Bob to manage position
            await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, BobAddress, true);
            expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, BobAddress)).to.be.equal(true);

            // 4. bob proxy wallet allow Bob address to manage position
            await PositionHelper.allowManagePosition(bobProxyWallet, BobAddress, 2, BobAddress, true);
            expect(await positionManager.ownerWhitelist(bobProxyWallet.address, 2, BobAddress)).to.be.equal(true);

            // 5. Bob try to move position to Alice position
            await expect(positionManager.connect(provider.getSigner(BobAddress)).movePosition(2, 1)).to.be.revertedWith("!same collateral pool");
          });
        });
      });
    });

    context("position owner not allow other user to manage position with user wallet address", async () => {
      context("move collateral", async () => {
        context("same collateral pool", async () => {
          context("and Bob move collateral of Alice to himself", async () => {
            it("should revert", async () => {
              // 1. Alice open a new position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position with 1 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Alice try to unlock 1 WXDC at her position
              await PositionHelper.adjustPosition(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                WeiPerWad.mul(-1),
                0
              );
              const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
              ).to.be.equal(WeiPerWad);

              // 4. Bob try to move collateral of Alice position to Bob position
              await expect(
                PositionHelper.moveCollateral(
                  bobProxyWallet,
                  BobAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  bobPositionAddress,
                  WeiPerWad
                )
              ).to.be.revertedWith("owner not allowed");
            });
          });
        });
        context("between collateral pool", async () => {
          context("and Bob move collateral of Alice to himself", async () => {
            it("should revert", async () => {
              // 1. Alice open a new position with 2 WXDC and draw 1 FXD
              await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
              const alicePositionAddress = await positionManager.positions(1);
              const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
              const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
              ).to.be.equal(0);
              expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 2. Bob open a position at collateral pool 2 with 2 WXDC and draw 1 FXD
              await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad.mul(2), WeiPerWad);
              const bobPositionAddress = await positionManager.positions(2);
              const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
              const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
              expect(bobPosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Bob locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
              expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
              ).to.be.equal(0);
              expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
              // 3. Alice try to unlock 1 WXDC at her position
              await PositionHelper.adjustPosition(
                aliceProxyWallet,
                AliceAddress,
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                WeiPerWad.mul(-1),
                0,
                collateralTokenAdapter.address
              );
              const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
              expect(aliceAdjustPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC").to.be.equal(WeiPerWad);
              expect(aliceAdjustPosition.debtShare, "debtShare should be 1 FXD, because Alice didn't draw more").to.be.equal(WeiPerWad);
              expect(
                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC"
              ).to.be.equal(WeiPerWad);

              // 4. Bob try to move collateral of Alice position to his position
              await expect(
                PositionHelper.moveCollateral(
                  bobProxyWallet,
                  BobAddress,
                  await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                  bobPositionAddress,
                  WeiPerWad,
                  collateralTokenAdapter.address
                )
              ).to.be.revertedWith("owner not allowed");
            });
          });
        });
      });

      context("mint FXD", async () => {
        it("should revert", async () => {
          // 1. Alice open a new position with 1 WXDC and draw 1 FXD
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
          const alicePositionAddress = await positionManager.positions(1);
          const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
          const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
          expect(alicePosition.lockedCollateral, "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC").to.be.equal(WeiPerWad.mul(2));
          expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
          expect(
            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
          ).to.be.equal(0);
          expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

          // 2. Bob try to mint FXD at Alice position
          await expect(
            positionManager
              .connect(provider.getSigner(BobAddress))
              .adjustPosition(
                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                0,
                alicePosition.debtShare,
                ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress])
              )
          ).to.be.revertedWith("owner not allowed");
        });
      });

      context("move position", async () => {
        context("same collateral pool", async () => {
          it("should revert", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress);
            expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

            // 3. Bob try to move collateral to alice position
            await expect(positionManager.connect(provider.getSigner(BobAddress)).movePosition(2, 1)).to.be.revertedWith("owner not allowed");
          });
        });
        context("between 2 collateral pool", async () => {
          it("should revert", async () => {
            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
            const alicePositionAddress = await positionManager.positions(1);
            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
            expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
              "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
            ).to.be.equal(0);
            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);
            // 2. Bob open a position with 1 WXDC and draw 1 FXD at collateral pool id 2
            await PositionHelper.openPositionAndDraw(bobProxyWallet, BobAddress, pools.GLD, WeiPerWad, WeiPerWad);
            const bobPositionAddress = await positionManager.positions(2);
            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress);
            const bobPosition = await bookKeeper.positions(pools.GLD, bobPositionAddress);
            expect(bobPosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC").to.be.equal(WeiPerWad);
            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad);
            expect(
              await bookKeeper.collateralToken(pools.GLD, bobPositionAddress),
              "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
            ).to.be.equal(0);
            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

            // 3. Bob try to move position to Alice position
            await expect(positionManager.connect(provider.getSigner(BobAddress)).movePosition(2, 1)).to.be.revertedWith("owner not allowed");
          });
        });
      });
    });

    context("position owner can export and can import", async () => {
      it("should success", async () => {
        // 1. Alice open a new position with 1 WXDC and draw 1 FXD
        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
        const alicePositionAddress = await positionManager.positions(1);
        const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress);
        const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress);
        expect(alicePosition.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC").to.be.equal(WeiPerWad);
        expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad);
        expect(
          await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
          "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
        ).to.be.equal(0);
        expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad);

        // 2. alice allow manage position
        await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, AliceAddress, true);
        expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, AliceAddress)).to.be.equal(true);

        // 3. alice allow positionManage
        await bookKeeper.connect(provider.getSigner(AliceAddress)).whitelist(positionManager.address);

        // 4. alice allow migration
        await positionManager.connect(provider.getSigner(AliceAddress)).allowMigratePosition(aliceProxyWallet.address, true);
        expect(await positionManager.migrationWhitelist(AliceAddress, aliceProxyWallet.address)).to.be.equal(true);

        // 5. Alice export position
        await PositionHelper.exportPosition(aliceProxyWallet, AliceAddress, 1, AliceAddress);
        const alicePositionAfterExport = await bookKeeper.positions(pools.XDC, AliceAddress);
        expect(alicePositionAfterExport.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice export").to.be.equal(WeiPerWad);
        expect(alicePositionAfterExport.debtShare, "debtShare should be 1 FXD, because Alice export").to.be.equal(WeiPerWad);
        const alicePositionWalletPositionAfterExport = await bookKeeper.positions(pools.XDC, alicePositionAddress);
        expect(alicePositionWalletPositionAfterExport.lockedCollateral, "lockedCollateral should be 0 WXDC, because Alice export").to.be.equal(0);
        expect(alicePositionWalletPositionAfterExport.debtShare, "debtShare should be 0 FXD, because Alice export").to.be.equal(0);

        //6. alice import position back
        await PositionHelper.importPosition(aliceProxyWallet, AliceAddress, AliceAddress, 1);
        const alicePositionAfterImport = await bookKeeper.positions(pools.XDC, AliceAddress);
        expect(alicePositionAfterImport.lockedCollateral, "lockedCollateral should be 0 WXDC, because Alice Import").to.be.equal(0);
        expect(alicePositionAfterImport.debtShare, "debtShare should be 0 FXD, because Alice Import").to.be.equal(0);
        const alicePositionWalletPositionAfterImport = await bookKeeper.positions(pools.XDC, alicePositionAddress);
        expect(alicePositionWalletPositionAfterImport.lockedCollateral, "lockedCollateral should be 1 WXDC, because Alice Import").to.be.equal(
          WeiPerWad
        );
        expect(alicePositionWalletPositionAfterImport.debtShare, "debtShare should be 1 FXD, because Alice Import").to.be.equal(WeiPerWad);
      });
    });
    context("position ceiling", async () => {
      context("open position exceeds position ceiling", async () => {
        it("should revert", async () => {
          let values = [0];
          let targets = [
            simplePriceFeed.address,
          ];
          let calldatas = [
            simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay.div(1000)]),
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
          // await simplePriceFeed.setPrice(WeiPerRay.div(1000));

          await expect(
            PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2000), WeiPerWad.mul(1000001))
          ).to.be.revertedWith("BookKeeper/position-debt-ceiling-exceeded");
        });
      });
      context("adjust position exceeds position ceiling", async () => {
        it("should revert", async () => {
          let values = [0];
          let targets = [
            simplePriceFeed.address,
          ];
          let calldatas = [
            simplePriceFeed.interface.encodeFunctionData("setPrice", [WeiPerRay.div(1000)]),
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
          //  await simplePriceFeed.setPrice(WeiPerRay.div(1000));
          
          await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2000), WeiPerWad.mul(1000000));
          await expect(
            PositionHelper.adjustPosition(
              aliceProxyWallet,
              AliceAddress,
              await positionManager.ownerLastPositionId(aliceProxyWallet.address),
              0,
              WeiPerWad
            )
          ).to.be.revertedWith("BookKeeper/position-debt-ceiling-exceeded");
        });
      });
    });
  });
});