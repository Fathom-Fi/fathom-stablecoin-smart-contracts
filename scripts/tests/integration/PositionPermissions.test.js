const chai = require('chai');
const { ethers } = require("ethers");

const { solidity } = require("ethereum-waffle");
chai.use(solidity);

const { WeiPerRad, WeiPerRay, WeiPerWad } = require("../helper/unit");
const { createProxyWallets } = require("../helper/proxy-wallets");
const { AliceAddress, BobAddress } = require("../helper/address");
const PositionHelper = require("../helper/positions");
const { loadFixture } = require("../helper/fixtures");
const { getProxy } = require("../../common/proxies");
const pools = require("../../common/collateral");

const { expect } = chai

const setup = async () => {
    const proxyFactory = await artifacts.initializeInterfaceAt("FathomProxyFactory", "FathomProxyFactory");
    const simplePriceFeed = await artifacts.initializeInterfaceAt("SimplePriceFeed", "SimplePriceFeed");
    const fathomStablecoinProxyActions = await artifacts.initializeInterfaceAt("FathomStablecoinProxyActions", "FathomStablecoinProxyActions");

    const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    const positionManager = await getProxy(proxyFactory, "PositionManager");
    const stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
    const fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    const stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
    const priceOracle = await getProxy(proxyFactory, "PriceOracle");
    const collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
    const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");

    ({
        proxyWallets: [aliceProxyWallet, bobProxyWallet],
    } = await createProxyWallets([AliceAddress, BobAddress]));

    await simplePriceFeed.setPrice(WeiPerRay, { gasLimit: 1000000 });
    await collateralPoolConfig.setStabilityFeeRate(pools.XDC, WeiPerRay, { gasLimit: 1000000 });

    await priceOracle.setPrice(pools.XDC);

    return {
        bookKeeper,
        collateralTokenAdapter,
        positionManager,
        aliceProxyWallet,
        bobProxyWallet,
        fathomStablecoin,
        fathomStablecoinProxyActions,
        stablecoinAdapter,
        stabilityFeeCollector
    }
}

describe("PositionPermissions", () => {
    // Contracts
    let aliceProxyWallet
    let bobProxyWallet
    let collateralTokenAdapter
    let stablecoinAdapter
    let bookKeeper
    let positionManager
    let fathomStablecoinProxyActions
    let fathomStablecoin
    let stabilityFeeCollector

    before(async () => {
        await snapshot.revertToSnapshot();
    })

    beforeEach(async () => {
        ({
            bookKeeper,
            collateralTokenAdapter,
            positionManager,
            aliceProxyWallet,
            bobProxyWallet,
            fathomStablecoin,
            fathomStablecoinProxyActions,
            stablecoinAdapter,
            stabilityFeeCollector
        } = await loadFixture(setup));
    })

    describe("#permissions", async () => {
        context("position owner is able to", async () => {
            context("lock collateral into their own position", async () => {
                it("should success", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)

                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                    ).to.be.equal(WeiPerWad)
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                    // 2. Alice try to adjust position, add 2 WXDC to position
                    const posId = await positionManager.ownerLastPositionId(aliceProxyWallet.address)
                    const own = await positionManager.owners(1)
                    await PositionHelper.lockXDC(aliceProxyWallet, AliceAddress, 1, WeiPerWad.mul(2))
                    const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        aliceAdjustPosition.lockedCollateral,
                        "lockedCollateral should be 3 WXDC, because Alice locked 2 more WXDC"
                    ).to.be.equal(WeiPerWad.mul(3))
                    expect(
                        aliceAdjustPosition.debtShare,
                        "debtShare should be 1 FXD, because Alice didn't draw more"
                    ).to.be.equal(WeiPerWad)
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                })
            })

            context("move collateral", async () => {
                context("same collateral pool", async () => {
                    context(
                        "call openLockTokenAndDraw, unlock collateral and move the collateral from one position to another position within the same collateral pool",
                        async () => {
                            it("should success", async () => {
                                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                                const alicePositionAddress = await positionManager.positions(1)
                                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                                expect(
                                    alicePosition.lockedCollateral,
                                    "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                                ).to.be.equal(WeiPerWad)
                                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                    "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                                ).to.be.equal(0)
                                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                // 2. Alice open a second new position with 2 WXDC and draw 1 FXD at same collateral pool
                                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                                const alicePositionAddress2 = await positionManager.positions(2)
                                const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress)
                                const alicePosition2 = await bookKeeper.positions(pools.XDC, alicePositionAddress2)
                                expect(
                                    alicePosition2.lockedCollateral,
                                    "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                                ).to.be.equal(WeiPerWad.mul(2))
                                expect(alicePosition2.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                                ).to.be.equal(0)
                                expect(
                                    fathomStablecoinBalance2,
                                    "Alice should receive 2 FXD from drawing FXD 2 times form 2 positions"
                                ).to.be.equal(WeiPerWad.mul(2))
                                // 3. Alice try to unlock 1 WXDC at second position
                                await PositionHelper.adjustPosition(
                                    aliceProxyWallet,
                                    AliceAddress,
                                    await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                    WeiPerWad.mul(-1),
                                    0,
                                    collateralTokenAdapter.address
                                );
                                const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress2)
                                expect(
                                    aliceAdjustPosition.lockedCollateral,
                                    "Position #2's lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC from it"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    aliceAdjustPosition.debtShare,
                                    "debtShare should be 1 FXD, because Alice didn't draw more"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "collateralToken inside Alice's Position#2 address should be 1 WXDC, because Alice unlocked 1 WXDC from the position"
                                ).to.be.equal(WeiPerWad)
                                // 4. Alice try to move collateral from second position to first position
                                await PositionHelper.moveCollateral(
                                    aliceProxyWallet,
                                    AliceAddress,
                                    await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                    alicePositionAddress,
                                    WeiPerWad,
                                    collateralTokenAdapter.address,
                                );
                                const aliceMoveCollateral = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                                expect(
                                    aliceMoveCollateral.lockedCollateral,
                                    "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    aliceMoveCollateral.debtShare,
                                    "Alice's Position #1 debtShare should be 1 FXD, because Alice doesn't draw more"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                    "collateralToken inside Alice's Position #1 address should be 1 WXDC, because Alice moved 1 WXDC from Position #2 to Position #1."
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    fathomStablecoinBalancefinal,
                                    "Alice should receive 2 FXD from drawing 2 FXD, because Alice draw 2 times"
                                ).to.be.equal(WeiPerWad.mul(2))
                            })
                        }
                    )
                    context(
                        "open position, deposit collateral and move collateral from one position to another position",
                        async () => {
                            it("should success", async () => {
                                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                                const alicePositionAddress = await positionManager.positions(1)
                                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                                expect(
                                    alicePosition.lockedCollateral,
                                    "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                                ).to.be.equal(WeiPerWad)
                                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                    "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                                ).to.be.equal(0)
                                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                // 2. Alice open a second new position at same collateral pool
                                await PositionHelper.openPosition(aliceProxyWallet, AliceAddress, pools.XDC)
                                const alicePositionAddress2 = await positionManager.positions(2)
                                const alicePosition2 = await bookKeeper.positions(pools.XDC, alicePositionAddress2)
                                expect(
                                    alicePosition2.lockedCollateral,
                                    "lockedCollateral should be 0 WXDC, because Alice doesn't locked WXDC"
                                ).to.be.equal(0)
                                expect(alicePosition2.debtShare, "debtShare should be 0 FXD, because doesn't drew FXD").to.be.equal(0)
                                // 3. Alice deposit 3 WXDC to new position
                                await PositionHelper.xdcAdapterDeposit(
                                    aliceProxyWallet,
                                    AliceAddress,
                                    await positionManager.positions(2),
                                    WeiPerWad.mul(3),
                                );
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "collateralToken inside Alice's second position address should be 3 WXDC, because Alice deposit 3 WXDC into the second position"
                                ).to.be.equal(WeiPerWad.mul(3))
                                // 4. Alice try to move collateral from second position to first position
                                await PositionHelper.moveCollateral(
                                    aliceProxyWallet,
                                    AliceAddress,
                                    await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                    alicePositionAddress,
                                    WeiPerWad,
                                    collateralTokenAdapter.address,
                                );
                                const aliceMoveCollateral = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                                expect(
                                    aliceMoveCollateral.lockedCollateral,
                                    "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    aliceMoveCollateral.debtShare,
                                    "Alice's Position #1 debtShare should be 1 FXD, because Alice doesn't draw more"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                    "collateralToken inside Alice's Position #1 address should be 1 WXDC, because Alice moved 1 WXDC from Position #2 to Position #1."
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "collateralToken inside Alice's Position #2 address should be 2 WXDC, because Alice moved 1 WXDC to Position #1"
                                ).to.be.equal(WeiPerWad.mul(2))
                                expect(
                                    fathomStablecoinBalancefinal,
                                    "Alice should receive 1 FXD, because Alice draw 1 time"
                                ).to.be.equal(WeiPerWad)
                            })
                        }
                    )
                    context("Alice open a position, lock collateral and move collateral to Bob's position", async () => {
                        it("should success", async () => {
                            // 1. Alice open position
                            await PositionHelper.openPosition(aliceProxyWallet, AliceAddress, pools.XDC)
                            const alicePositionAddress = await positionManager.positions(1)
                            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                alicePosition.lockedCollateral,
                                "lockedCollateral should be 0 WXDC, because Alice doesn't locked WXDC"
                            ).to.be.equal(0)
                            expect(alicePosition.debtShare, "debtShare should be 0 FXD, because doesn't drew FXD").to.be.equal(0)
                            // 2. Alice deposit 3 WXDC to new position
                            await PositionHelper.xdcAdapterDeposit(
                                aliceProxyWallet,
                                AliceAddress,
                                await positionManager.positions(1),
                                WeiPerWad.mul(3),
                            );
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's second position address should be 3 WXDC, because Alice deposit 3 WXDC into the second position"
                            ).to.be.equal(WeiPerWad.mul(3))
                            // 3. Bob open a position with 1 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);

                            const bobPositionAddress = await positionManager.positions(2)
                            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                            expect(
                                bobPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(fathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 4. Alice try to move collateral to bob position
                            await PositionHelper.moveCollateral(
                                aliceProxyWallet,
                                AliceAddress,
                                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                bobPositionAddress,
                                WeiPerWad,
                                collateralTokenAdapter.address,
                            );
                            const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                            const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's Position address should be 2 WXDC, because Alice move 1 WXDC from Alice's Position to Bob's Position."
                            ).to.be.equal(WeiPerWad.mul(2))
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's Position address should be 1 WXDC, because Alice moved 1 WXDC from Alice's Position to Bob's position"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                aliceFathomStablecoinBalancefinal,
                                "Alice should receive 0 FXD, because Alice doesn't draw"
                            ).to.be.equal(0)
                            expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob draw 1 time").to.be.equal(
                                WeiPerWad
                            )
                        })
                    })
                })
            })

            context("mint FXD", async () => {
                it("should success", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)

                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)

                    // 2. Alice try to mint FXD
                    await PositionHelper.draw(
                        aliceProxyWallet,
                        AliceAddress,
                        pools.XDC,
                        await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                        WeiPerWad
                    );
                    const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress)
                    const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        aliceAdjustPosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice doesn't add WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(aliceAdjustPosition.debtShare, "debtShare should be 2 FXD, because Alice drew more").to.be.equal(
                        WeiPerWad.mul(2)
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance2, "Alice should receive 2 FXD from drawing 2 FXD").to.be.equal(
                        WeiPerWad.mul(2)
                    )
                })
            })

            context("move position", async () => {
                context("same collateral pool", async () => {
                    context(
                        "call openLockTokenAndDraw, unlock collateral and move the collateral from one position to another position within the same collateral pool",
                        async () => {
                            it("should success", async () => {
                                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                                const alicePositionAddress = await positionManager.positions(1)
                                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)

                                expect(
                                    alicePosition.lockedCollateral,
                                    "Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                                ).to.be.equal(WeiPerWad)
                                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                    "Alice's Position #1 collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                                ).to.be.equal(0)
                                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(
                                    WeiPerWad
                                )

                                // 2. Alice open a second new position with 2 WXDC and draw 1 FXD at same collateral pool
                                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                                const alicePositionAddress2 = await positionManager.positions(2)
                                const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress)
                                const alicePosition2 = await bookKeeper.positions(pools.XDC, alicePositionAddress2)

                                expect(
                                    alicePosition2.lockedCollateral,
                                    "Alice's Position #2 lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                                ).to.be.equal(WeiPerWad.mul(2))
                                expect(alicePosition2.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                    WeiPerWad
                                )
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "Alice's Position #2 collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                                ).to.be.equal(0)
                                expect(
                                    fathomStablecoinBalance2,
                                    "Alice should receive 2 FXD, because Alice drew FXD 2 times form 2 positions"
                                ).to.be.equal(WeiPerWad.mul(2))

                                // 3. Alice try to unlock 1 WXDC at second position
                                await PositionHelper.adjustPosition(
                                    aliceProxyWallet,
                                    AliceAddress,
                                    await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                    WeiPerWad.mul(-1),
                                    0,
                                    collateralTokenAdapter.address
                                );
                                const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress2)
                                expect(
                                    aliceAdjustPosition.lockedCollateral,
                                    "Alice's Position #2 lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    aliceAdjustPosition.debtShare,
                                    "Alice's Position #2 debtShare should be 1 FXD, because Alice didn't draw more"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "Alice's Position #2 collateralToken should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                                ).to.be.equal(WeiPerWad)

                                // 4. Alice try to move position from second position to first position
                                await PositionHelper.movePosition(aliceProxyWallet, AliceAddress, 2, 1)
                                const alicemovePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                                const fathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                                expect(
                                    alicemovePosition.lockedCollateral,
                                    "Alice's Position #1 lockedCollateral should be 2 WXDC, because Alice move form Position #2 to Postion #1"
                                ).to.be.equal(WeiPerWad.mul(2))
                                expect(
                                    alicemovePosition.debtShare,
                                    "Alice's Position #1 debtShare should be 2 FXD, because Alice move form Position #2 to Postion #1"
                                ).to.be.equal(WeiPerWad.mul(2))
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress2),
                                    "collateralToken inside Alice's Position #2 address should still be 1 WXDC, because Alice moving position will not move collateral"
                                ).to.be.equal(WeiPerWad)
                                expect(
                                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                    "collateralToken inside Alice's Position #1 address should still be 0 WXDC, because Alice moving position will not move collateral"
                                ).to.be.equal(0)
                                expect(
                                    fathomStablecoinBalancefinal,
                                    "Alice should receive 2 FXD from drawing 2 FXD, because Alice drew 2 times"
                                ).to.be.equal(WeiPerWad.mul(2))
                                const alicePosition1Stake = await collateralTokenAdapter.stake(alicePositionAddress)
                                expect(alicePosition1Stake, "Stake must be correctly updated after movePosition").to.be.equal(
                                    WeiPerWad.mul(2)
                                )
                            })
                        }
                    )
                })
            })
        })

        context("position owner allow other user to manage position with proxy wallet", async () => {
            context("lock collateral into their own position", async () => {
                it("should success", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                    ).to.be.equal(WeiPerWad)
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                    // 2. Alice allow Bob to manage position
                    await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, 1)
                    expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(
                        1
                    )
                    // 3. Bob try to adjust Alice's position, add 2 WXDC to position
                    await PositionHelper.lockXDC(bobProxyWallet, BobAddress, 1, WeiPerWad.mul(2))

                    const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        aliceAdjustPosition.lockedCollateral,
                        "lockedCollateral should be 3 WXDC, because Bob add locked 2 WXDC"
                    ).to.be.equal(WeiPerWad.mul(3))
                })
            })
            context("move collateral", async () => {
                context("same collateral pool", async () => {
                    context("and Bob move collateral of Alice to himself", async () => {
                        it("should success", async () => {
                            // 1. Alice open a new position with 2 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                            const alicePositionAddress = await positionManager.positions(1)
                            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                alicePosition.lockedCollateral,
                                "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                            ).to.be.equal(WeiPerWad.mul(2))
                            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 2. Bob open a position with 1 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                            const bobPositionAddress = await positionManager.positions(2)
                            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                            expect(
                                bobPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 3. Alice try to unlock 1 WXDC at her position
                            await PositionHelper.adjustPosition(
                                aliceProxyWallet,
                                AliceAddress,
                                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                WeiPerWad.mul(-1),
                                0,
                                collateralTokenAdapter.address
                            );
                            const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                aliceAdjustPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                aliceAdjustPosition.debtShare,
                                "debtShare should be 1 FXD, because Alice doesn't draw more"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                            ).to.be.equal(WeiPerWad)
                            // 4. Alice allow Bob to manage position
                            await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, 1)
                            expect(
                                await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)
                            ).to.be.equal(1)
                            // 5. Bob try to move collateral to Alice position
                            await PositionHelper.moveCollateral(
                                bobProxyWallet,
                                BobAddress,
                                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                bobPositionAddress,
                                WeiPerWad,
                                collateralTokenAdapter.address,
                            );
                            const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                            const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC of Alice's position to his position"
                            ).to.be.equal(0)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob move 1 WXDC of Alice's position to his position"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                aliceFathomStablecoinBalancefinal,
                                "Alice should receive 1 FXD, because Alice drew 1 time"
                            ).to.be.equal(WeiPerWad)
                            expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(
                                WeiPerWad
                            )
                        })
                    })
                })
            })
            context("mint FXD", async () => {
                it("should success", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                    // 2. Alice allow Bob to manage position
                    await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, 1)
                    expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(
                        1
                    )
                    // 3. Bob try to mint FXD at Alice position
                    await PositionHelper.draw(
                        bobProxyWallet,
                        BobAddress,
                        pools.XDC,
                        await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                        WeiPerWad
                    )
                    const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress)
                    const BobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                    const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        aliceAdjustPosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice didn't add WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(aliceAdjustPosition.debtShare, "debtShare should be 2 FXD, because Alice drew more").to.be.equal(
                        WeiPerWad.mul(2)
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance2, "Alice should receive 1 FXD from Alice drew 1 time").to.be.equal(WeiPerWad)
                    expect(BobFathomStablecoinBalance, "Bob should receive 1 FXD from mint Ausd at Alice position").to.be.equal(
                        WeiPerWad
                    )
                })
            })
            context("move position", async () => {
                context("same collateral pool", async () => {
                    it("should success", async () => {
                        // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                        const alicePositionAddress = await positionManager.positions(1)
                        const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                        const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                        expect(
                            alicePosition.lockedCollateral,
                            "Collateral Pool #1 inside Alice's Position #1 lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(
                            alicePosition.debtShare,
                            "Collateral Pool #1 inside Alice's Position #1 debtShare should be 1 FXD, because Alice drew 1 FXD"
                        ).to.be.equal(WeiPerWad)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 2. Bob open a position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const bobPositionAddress = await positionManager.positions(2)
                        const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                        const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                        expect(
                            bobPosition.lockedCollateral,
                            "Collateral Pool #1 inside Bob's Position #1 lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(
                            bobPosition.debtShare,
                            "Collateral Pool #1 inside Bob's Position #1 debtShare should be 1 FXD, because Bob drew 1 FXD"
                        ).to.be.equal(WeiPerWad)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                            "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 3. Alice allow Bob to manage position
                        await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, 1)
                        expect(
                            await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)
                        ).to.be.equal(1)
                        // 4. Bob try to move collateral to alice position
                        await PositionHelper.movePosition(bobProxyWallet, BobAddress, 2, 1)
                        const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                        const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress)
                        const alicePositionAfterMovePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                        expect(
                            alicePositionAfterMovePosition.lockedCollateral,
                            "Collateral Pool #1 inside Alice's Position #1 lockedCollateral should be 2 WXDC, because Bob move locked 1 WXDC to Alice"
                        ).to.be.equal(WeiPerWad.mul(2))
                        expect(
                            alicePositionAfterMovePosition.debtShare,
                            "Collateral Pool #1 inside Alice's Position #1 debtShare should be 1 FXD, because Bob move DebtShare to Alice"
                        ).to.be.equal(WeiPerWad.mul(2))
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                            "collateralToken inside Alice's position address should be 0 WXDC, because Alice all lock collateral"
                        ).to.be.equal(0)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                            "collateralToken inside Bob's position address should be 0 WXDC, because Bob all lock collateral"
                        ).to.be.equal(0)
                        expect(
                            aliceFathomStablecoinBalancefinal,
                            "Alice should receive 1 FXD, because Alice drew 1 time"
                        ).to.be.equal(WeiPerWad)
                        expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(
                            WeiPerWad
                        )
                    })
                })
            })
        })

        context("position owner not allow other user to manage position with proxy wallet", async () => {
            context("lock collateral into their own position", async () => {
                it("should revert", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                    ).to.be.equal(WeiPerWad)
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)

                    // 2. Bob try to adjust Alice's position, add 2 WXDC to position
                    const lockAbi = [
                        "function lockXDC(address _manager, address _xdcAdapter, uint256 _positionId, bytes calldata _data)"
                    ];
                    let lockIFace = new ethers.utils.Interface(lockAbi);
                    const lockTokenCall = lockIFace.encodeFunctionData("lockXDC", [
                        positionManager.address,
                        collateralTokenAdapter.address,
                        await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                        ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]),
                    ])

                    await expect(
                        bobProxyWallet.execute(lockTokenCall, { value: WeiPerWad, from: BobAddress })
                    ).to.be.revertedWith("owner not allowed")
                })
            })
            context("move collateral", async () => {
                context("same collateral pool", async () => {
                    context("and Bob move collateral to Alice", async () => {
                        it("should success", async () => {
                            // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);

                            const alicePositionAddress = await positionManager.positions(1)
                            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                alicePosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 2. Bob open a position with 2 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
                            const bobPositionAddress = await positionManager.positions(2)
                            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                            expect(
                                bobPosition.lockedCollateral,
                                "lockedCollateral should be 2 WXDC, because Bob locked 2 WXDC"
                            ).to.be.equal(WeiPerWad.mul(2))
                            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 3. Bob try to unlock 1 WXDC at second position
                            await PositionHelper.adjustPosition(
                                bobProxyWallet,
                                BobAddress,
                                await positionManager.ownerLastPositionId(bobProxyWallet.address),
                                WeiPerWad.mul(-1),
                                0,
                                collateralTokenAdapter.address
                            );
                            const bobAdjustPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                            expect(
                                bobAdjustPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Bob unlocked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                bobAdjustPosition.debtShare,
                                "debtShare should be 1 FXD, because Bob doesn't draw more"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 1 WXDC, because Bob unlocked 1 WXDC into the position"
                            ).to.be.equal(WeiPerWad)
                            // 4. Bob try to move collateral to Alice position
                            await PositionHelper.moveCollateral(
                                bobProxyWallet,
                                BobAddress,
                                await positionManager.ownerLastPositionId(bobProxyWallet.address),
                                alicePositionAddress,
                                WeiPerWad,
                                collateralTokenAdapter.address,
                            );
                            const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                            const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 1 WXDC, because Bob move 1 WXDC to Alice's position"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob move 1 WXDC to Alice's position"
                            ).to.be.equal(0)
                            expect(
                                aliceFathomStablecoinBalancefinal,
                                "Alice should receive 1 FXD, because Alice drew 1 time"
                            ).to.be.equal(WeiPerWad)
                            expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(
                                WeiPerWad
                            )
                        })
                    })
                })
            })
            context("mint FXD", async () => {
                it("should revert", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);

                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                    // 2. Bob try to mint FXD at Alice position
                    let drawTokenAbi = [
                        "function draw(address _manager, address _stabilityFeeCollector, address _tokenAdapter, address _stablecoinAdapter, uint256 _positionId, uint256 _amount, bytes calldata _data)"
                    ];
                    let drawTokenIFace = new ethers.utils.Interface(drawTokenAbi);
                    let drawTokenCall = drawTokenIFace.encodeFunctionData("draw", [
                        positionManager.address,
                        stabilityFeeCollector.address,
                        collateralTokenAdapter.address,
                        stablecoinAdapter.address,
                        await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                        WeiPerWad,
                        ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]),
                    ])
                    await expect(
                        bobProxyWallet.execute(drawTokenCall, { from: BobAddress })
                    ).to.be.revertedWith("owner not allowed")
                })
            })
            context("move position", async () => {
                context("same collateral pool", async () => {
                    it("should revert", async () => {
                        // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const alicePositionAddress = await positionManager.positions(1)
                        const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                        const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                        expect(
                            alicePosition.lockedCollateral,
                            "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                            WeiPerWad
                        )
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 2. Bob open a position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const bobPositionAddress = await positionManager.positions(2)
                        const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                        const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                        expect(
                            bobPosition.lockedCollateral,
                            "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                            "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 3. Bob try to move collateral to alice position
                        const movePositionAbi = [
                            "function movePosition(address _manager, uint256 _source, uint256 _destination)"
                        ];
                        const movePositionIFace = new ethers.utils.Interface(movePositionAbi);
                        const movePositionCall = movePositionIFace.encodeFunctionData("movePosition", [
                            positionManager.address,
                            2,
                            1,
                        ])
                        await expect(
                            bobProxyWallet.execute(movePositionCall, { from: BobAddress })
                        ).to.be.revertedWith("owner not allowed")
                    })
                })
            })
        })

        context("position owner allow other user to manage position with user wallet address", async () => {
            context("move collateral", async () => {
                context("same collateral pool", async () => {
                    context("and Bob move collateral of Alice to himself", async () => {
                        it("should success", async () => {
                            // 1. Alice open a new position with 2 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
                            const alicePositionAddress = await positionManager.positions(1)
                            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                alicePosition.lockedCollateral,
                                "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                            ).to.be.equal(WeiPerWad.mul(2))
                            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 2. Bob open a position with 1 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                            const bobPositionAddress = await positionManager.positions(2)
                            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                            expect(
                                bobPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 3. Alice try to unlock 1 WXDC at her position
                            await PositionHelper.adjustPosition(
                                aliceProxyWallet,
                                AliceAddress,
                                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                WeiPerWad.mul(-1),
                                0,
                                collateralTokenAdapter.address
                            );
                            const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                aliceAdjustPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                aliceAdjustPosition.debtShare,
                                "debtShare should be 1 FXD, because Alice didn't draw more"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                            ).to.be.equal(WeiPerWad)

                            // 4. Alice allow Bob to manage position
                            await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, bobProxyWallet.address, 1)
                            expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, bobProxyWallet.address)).to.be.equal(1)

                            // 5. Bob try to move collateral of Alice position to Bob position
                            //   await positionManager["moveCollateral(uint256,address,uint256,address,bytes)"](
                            await PositionHelper.moveCollateral(
                                bobProxyWallet,
                                BobAddress,
                                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                bobPositionAddress,
                                WeiPerWad,
                                collateralTokenAdapter.address
                            )

                            const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                            const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 0 WXDC, because Bob move 1 WXDC to his position"
                            ).to.be.equal(0)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Alice's position address should be 1 WXDC, because Bob move 1 WXDC to his position"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                aliceFathomStablecoinBalancefinal,
                                "Alice should receive 1 FXD, because Alice drew 1 time"
                            ).to.be.equal(WeiPerWad)
                            expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(
                                WeiPerWad
                            )
                        })
                    })
                })
            })
            context("mint FXD", async () => {
                it("should success", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                    // 2. Alice allow Bob to manage position
                    await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, BobAddress, 1)
                    expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, BobAddress)).to.be.equal(1)
                    // 3. Bob try to mint FXD at Alice position
                    await positionManager.adjustPosition(
                        await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                        0,
                        alicePosition.debtShare,
                        collateralTokenAdapter.address,
                        ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]),
                        { from: BobAddress }
                    )

                    // 4. move stablecoin of alice to bob
                    await positionManager.moveStablecoin(
                        await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                        BobAddress,
                        WeiPerRad,
                        { from: BobAddress }
                    )

                    // 5. allow bob to window
                    await bookKeeper.whitelist(stablecoinAdapter.address, { from: BobAddress })

                    // 6. mint ausd
                    await stablecoinAdapter.withdraw(
                        BobAddress,
                        WeiPerWad,
                        ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]),
                        { from: BobAddress }
                    )
                    const fathomStablecoinBalance2 = await fathomStablecoin.balanceOf(AliceAddress)
                    const BobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                    const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        aliceAdjustPosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice doesn't add WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(aliceAdjustPosition.debtShare, "debtShare should be 2 FXD, because Alice drew more").to.be.equal(
                        WeiPerWad.mul(2)
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance2, "Alice should receive 1 FXD, because Alice drew 1 time").to.be.equal(
                        WeiPerWad
                    )
                    expect(BobFathomStablecoinBalance, "Bob should receive 1 FXD from Alice position").to.be.equal(WeiPerWad)
                })
            })
            context("move position", async () => {
                context("same collateral pool", async () => {
                    it("should success", async () => {
                        // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const alicePositionAddress = await positionManager.positions(1)
                        const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                        const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                        expect(
                            alicePosition.lockedCollateral,
                            "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                            WeiPerWad
                        )
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 2. Bob open a position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const bobPositionAddress = await positionManager.positions(2)
                        const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                        const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                        expect(
                            bobPosition.lockedCollateral,
                            "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                            "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 3. Alice allow Bob to manage position
                        await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, BobAddress, 1)
                        expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, BobAddress)).to.be.equal(1)

                        // 4. bob proxy wallet allow Bob address to manage position
                        await PositionHelper.allowManagePosition(bobProxyWallet, BobAddress, 2, BobAddress, 1)
                        expect(await positionManager.ownerWhitelist(bobProxyWallet.address, 2, BobAddress)).to.be.equal(1)

                        // 5. Bob try to move collateral to alice position
                        await positionManager.movePosition(2, 1, { from: BobAddress })
                        const aliceFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(AliceAddress)
                        const bobFathomStablecoinBalancefinal = await fathomStablecoin.balanceOf(BobAddress)
                        const alicePositionAfterMovePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                        expect(
                            alicePositionAfterMovePosition.lockedCollateral,
                            "lockedCollateral should be 2 WXDC, because Bob move locked 1 WXDC to Alice"
                        ).to.be.equal(WeiPerWad.mul(2))
                        expect(
                            alicePositionAfterMovePosition.debtShare,
                            "debtShare should be 1 FXD, because Bob move DebtShare to Alice"
                        ).to.be.equal(WeiPerWad.mul(2))
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                            "collateralToken inside Alice's position address should be 0 WXDC, because Alice all lock collateral"
                        ).to.be.equal(0)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                            "collateralToken inside Bob's position address should be 0 WXDC, because Bob all lock collateral"
                        ).to.be.equal(0)
                        expect(
                            aliceFathomStablecoinBalancefinal,
                            "Alice should receive 1 FXD, because Alice drew 1 time"
                        ).to.be.equal(WeiPerWad)
                        expect(bobFathomStablecoinBalancefinal, "Bob should receive 1 FXD, because Bob drew 1 time").to.be.equal(
                            WeiPerWad
                        )
                    })
                })
            })
        })

        context("position owner not allow other user to manage position with user wallet address", async () => {
            context("move collateral", async () => {
                context("same collateral pool", async () => {
                    context("and Bob move collateral of Alice to himself", async () => {
                        it("should revert", async () => {
                            // 1. Alice open a new position with 2 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
                            const alicePositionAddress = await positionManager.positions(1)
                            const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                            const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                alicePosition.lockedCollateral,
                                "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                            ).to.be.equal(WeiPerWad.mul(2))
                            expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 2. Bob open a position with 1 WXDC and draw 1 FXD
                            await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                            const bobPositionAddress = await positionManager.positions(2)
                            const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                            const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                            expect(
                                bobPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(
                                WeiPerWad
                            )
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                                "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                            ).to.be.equal(0)
                            expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                            // 3. Alice try to unlock 1 WXDC at her position
                            await PositionHelper.adjustPosition(
                                aliceProxyWallet,
                                AliceAddress,
                                await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                WeiPerWad.mul(-1),
                                0,
                                collateralTokenAdapter.address
                            );
                            const aliceAdjustPosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                            expect(
                                aliceAdjustPosition.lockedCollateral,
                                "lockedCollateral should be 1 WXDC, because Alice unlocked 1 WXDC"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                aliceAdjustPosition.debtShare,
                                "debtShare should be 1 FXD, because Alice didn't draw more"
                            ).to.be.equal(WeiPerWad)
                            expect(
                                await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                                "collateralToken inside Alice's position address should be 1 WXDC, because Alice unlocked 1 WXDC into the position"
                            ).to.be.equal(WeiPerWad)

                            // 4. Bob try to move collateral of Alice position to Bob position
                            await expect(
                                PositionHelper.moveCollateral(
                                    bobProxyWallet,
                                    BobAddress,
                                    await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                                    bobPositionAddress,
                                    WeiPerWad,
                                    collateralTokenAdapter.address
                                )
                            ).to.be.revertedWith("owner not allowed")
                        })
                    })
                })
            })

            context("mint FXD", async () => {
                it("should revert", async () => {
                    // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                    await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(2), WeiPerWad);
                    const alicePositionAddress = await positionManager.positions(1)
                    const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                    const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                    expect(
                        alicePosition.lockedCollateral,
                        "lockedCollateral should be 2 WXDC, because Alice locked 2 WXDC"
                    ).to.be.equal(WeiPerWad.mul(2))
                    expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                        WeiPerWad
                    )
                    expect(
                        await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                        "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                    ).to.be.equal(0)
                    expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)

                    // 2. Bob try to mint FXD at Alice position
                    await expect(
                        positionManager.adjustPosition(
                            await positionManager.ownerLastPositionId(aliceProxyWallet.address),
                            0,
                            alicePosition.debtShare,
                            collateralTokenAdapter.address,
                            ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]),
                            { from: BobAddress }
                        )
                    ).to.be.revertedWith("owner not allowed")
                })
            })

            context("move position", async () => {
                context("same collateral pool", async () => {
                    it("should revert", async () => {
                        // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const alicePositionAddress = await positionManager.positions(1)
                        const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                        const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                        expect(
                            alicePosition.lockedCollateral,
                            "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(
                            WeiPerWad
                        )
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                            "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)
                        // 2. Bob open a position with 1 WXDC and draw 1 FXD
                        await PositionHelper.openXDCPositionAndDraw(bobProxyWallet, BobAddress, pools.XDC, WeiPerWad, WeiPerWad);
                        const bobPositionAddress = await positionManager.positions(2)
                        const bobFathomStablecoinBalance = await fathomStablecoin.balanceOf(BobAddress)
                        const bobPosition = await bookKeeper.positions(pools.XDC, bobPositionAddress)
                        expect(
                            bobPosition.lockedCollateral,
                            "lockedCollateral should be 1 WXDC, because Bob locked 1 WXDC"
                        ).to.be.equal(WeiPerWad)
                        expect(bobPosition.debtShare, "debtShare should be 1 FXD, because Bob drew 1 FXD").to.be.equal(WeiPerWad)
                        expect(
                            await bookKeeper.collateralToken(pools.XDC, bobPositionAddress),
                            "collateralToken inside Bob's position address should be 0 WXDC, because Bob locked all WXDC into the position"
                        ).to.be.equal(0)
                        expect(bobFathomStablecoinBalance, "Bob should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)

                        // 3. Bob try to move collateral to alice position
                        await expect(positionManager.movePosition(2, 1, { from: BobAddress })).to.be.revertedWith("owner not allowed")
                    })
                })
            })
        })

        context("position owner can export and can import", async () => {
            it("should success", async () => {
                // 1. Alice open a new position with 1 WXDC and draw 1 FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad, WeiPerWad);
                const alicePositionAddress = await positionManager.positions(1)
                const fathomStablecoinBalance = await fathomStablecoin.balanceOf(AliceAddress)
                const alicePosition = await bookKeeper.positions(pools.XDC, alicePositionAddress)
                expect(
                    alicePosition.lockedCollateral,
                    "lockedCollateral should be 1 WXDC, because Alice locked 1 WXDC"
                ).to.be.equal(WeiPerWad)
                expect(alicePosition.debtShare, "debtShare should be 1 FXD, because Alice drew 1 FXD").to.be.equal(WeiPerWad)
                expect(
                    await bookKeeper.collateralToken(pools.XDC, alicePositionAddress),
                    "collateralToken inside Alice's position address should be 0 WXDC, because Alice locked all WXDC into the position"
                ).to.be.equal(0)
                expect(fathomStablecoinBalance, "Alice should receive 1 FXD from drawing 1 FXD").to.be.equal(WeiPerWad)

                // 2. alice allow manage position
                await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, AliceAddress, 1)
                expect(await positionManager.ownerWhitelist(aliceProxyWallet.address, 1, AliceAddress)).to.be.equal(1)

                // 3. alice allow positionManage
                await bookKeeper.whitelist(positionManager.address, { from: AliceAddress })

                // 4. alice allow migration
                await positionManager.allowMigratePosition(aliceProxyWallet.address, 1, { from: AliceAddress })
                expect(await positionManager.migrationWhitelist(AliceAddress, aliceProxyWallet.address)).to.be.equal(1)

                // 5. Alice export position
                await PositionHelper.exportPosition(aliceProxyWallet, AliceAddress, 1, AliceAddress)
                const alicePositionAfterExport = await bookKeeper.positions(pools.XDC, AliceAddress)
                expect(
                    alicePositionAfterExport.lockedCollateral,
                    "lockedCollateral should be 1 WXDC, because Alice export"
                ).to.be.equal(WeiPerWad)
                expect(alicePositionAfterExport.debtShare, "debtShare should be 1 FXD, because Alice export").to.be.equal(
                    WeiPerWad
                )
                const alicePositionWalletPositionAfterExport = await bookKeeper.positions(
                    pools.XDC,
                    alicePositionAddress
                )
                expect(
                    alicePositionWalletPositionAfterExport.lockedCollateral,
                    "lockedCollateral should be 0 WXDC, because Alice export"
                ).to.be.equal(0)
                expect(
                    alicePositionWalletPositionAfterExport.debtShare,
                    "debtShare should be 0 FXD, because Alice export"
                ).to.be.equal(0)
                const AliceAddressStake = await collateralTokenAdapter.stake(AliceAddress)
                expect(AliceAddressStake, "Stake must be correctly updated after exportPosition").to.be.equal(WeiPerWad)

                //6. alice import position back
                await PositionHelper.importPosition(aliceProxyWallet, AliceAddress, AliceAddress, 1);
                const alicePositionAfterImport = await bookKeeper.positions(pools.XDC, AliceAddress)
                expect(
                    alicePositionAfterImport.lockedCollateral,
                    "lockedCollateral should be 0 WXDC, because Alice Import"
                ).to.be.equal(0)
                expect(alicePositionAfterImport.debtShare, "debtShare should be 0 FXD, because Alice Import").to.be.equal(0)
                const alicePositionWalletPositionAfterImport = await bookKeeper.positions(
                    pools.XDC,
                    alicePositionAddress
                )
                expect(
                    alicePositionWalletPositionAfterImport.lockedCollateral,
                    "lockedCollateral should be 1 WXDC, because Alice Import"
                ).to.be.equal(WeiPerWad)
                expect(
                    alicePositionWalletPositionAfterImport.debtShare,
                    "debtShare should be 1 FXD, because Alice Import"
                ).to.be.equal(WeiPerWad)
                const alicePositionStake = await collateralTokenAdapter.stake(alicePositionAddress)
                expect(alicePositionStake, "Stake must be correctly updated after importPosition").to.be.equal(WeiPerWad)

            })
        })
    })
})
