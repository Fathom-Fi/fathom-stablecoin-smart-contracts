const chai = require('chai');

const { solidity } = require("ethereum-waffle");
chai.use(solidity);
const { expect } = chai


const { WeiPerRay, WeiPerWad } = require("../helper/unit");
const AssertHelpers = require("../helper/assert");
const { createProxyWallets } = require("../helper/proxy-wallets");
const { AliceAddress, DevAddress } = require("../helper/address");
const PositionHelper = require("../helper/positions");
const { loadFixture } = require("../helper/fixtures");
const { getProxy } = require("../../common/proxies");
const pools = require("../../common/collateral");

const setup = async () => {
    const proxyFactory = await artifacts.initializeInterfaceAt("FathomProxyFactory", "FathomProxyFactory");
    const simplePriceFeed = await artifacts.initializeInterfaceAt("SimplePriceFeed", "SimplePriceFeed");

    const collateralPoolConfig = await getProxy(proxyFactory, "CollateralPoolConfig");
    const bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    const stabilityFeeCollector = await getProxy(proxyFactory, "StabilityFeeCollector");
    const positionManager = await getProxy(proxyFactory, "PositionManager");
    const stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
    const fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    const proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");
    await proxyWalletRegistry.setDecentralizedMode(true);

    ({
        proxyWallets: [aliceProxyWallet],
    } = await createProxyWallets([AliceAddress]));
    const reentrancyAttacker = await artifacts.initializeInterfaceAt("ReentrancyAttacker", "ReentrancyAttacker");
    const reentrancyAttacker2 = await artifacts.initializeInterfaceAt("ReentrancyAttacker2", "ReentrancyAttacker2");

    //making proxyWallet of reentrancyAttacker contract
    await proxyWalletRegistry.build(reentrancyAttacker.address);
    await proxyWalletRegistry.build(reentrancyAttacker2.address);

    const reEntrantProxyWallet = await proxyWalletRegistry.proxies(reentrancyAttacker.address);
    const reEntrantProxyWallet2 = await proxyWalletRegistry.proxies(reentrancyAttacker2.address);

    await reentrancyAttacker.setProxyWallet(reEntrantProxyWallet);
    await reentrancyAttacker2.setProxyWallet(reEntrantProxyWallet2);


    await stabilityFeeCollector.setSystemDebtEngine(DevAddress)

    await fathomStablecoin.approve(aliceProxyWallet.address, WeiPerWad.mul(10000), { from: AliceAddress })

    return {
        bookKeeper,
        stablecoinAdapter,
        positionManager,
        stabilityFeeCollector,
        simplePriceFeed,
        collateralPoolConfig,
        aliceProxyWallet,
        reEntrantProxyWallet,
        reEntrantProxyWallet2,
        reentrancyAttacker,
        reentrancyAttacker2,
        fathomStablecoin
    }
}

describe("Position Closure without collateral withdrawl", () => {
    // Proxy wallet
    let aliceProxyWallet

    // Contract
    let positionManager
    let bookKeeper
    let simplePriceFeed

    before(async () => {
        await snapshot.revertToSnapshot();
    })

    beforeEach(async () => {
        ({
            bookKeeper,
            stablecoinAdapter,
            positionManager,
            // tokenAdapter,
            stabilityFeeCollector,
            simplePriceFeed,
            collateralPoolConfig,
            aliceProxyWallet,
            reEntrantProxyWallet,
            reEntrantProxyWallet2,
            reentrancyAttacker,
            reentrancyAttacker2,
            fathomStablecoin
        } = await loadFixture(setup));
    })

    describe("#wipeAndUnlockXDC", () => {
        context("open position and pay back debt without collateral withdrawl", () => {
            it("should be success", async () => {
                await simplePriceFeed.setPrice(WeiPerRay, { gasLimit: 1000000 })

                // position 1
                //  a. open a new position
                //  b. lock WXDC
                //  c. mint FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5))

                const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address)
                const positionAddress = await positionManager.positions(positionId)

                //  a. repay 2 WAD of FXD
                //  b. alice doesn't unlock any XDC
                //  c. check if the position has the same amount of lockedCollateral
                //  d. check if the position has now debtShare of 3 WAD (5-2)

                await PositionHelper.wipeAndUnlockXDC(
                    aliceProxyWallet,
                    AliceAddress,
                    positionId,
                    0,
                    WeiPerWad.mul(2)
                )

                const [lockedCollateral, debtShare] = await bookKeeper.positions(
                    pools.XDC,
                    positionAddress
                )

                expect(lockedCollateral).to.be.equal(WeiPerWad.mul(10));
                AssertHelpers.assertAlmostEqual(
                    debtShare,
                    WeiPerWad.mul(3)
                )
            })
        })
        context("try reentry with ReentrancyAttacker", () => {
            it("should not make change to the position", async () => {
                await simplePriceFeed.setPrice(WeiPerRay, { gasLimit: 1000000 })

                // position 1
                //  a. open a new position
                //  b. lock WXDC
                //  c. mint FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5))

                const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address)
                const positionAddress = await positionManager.positions(positionId)
                
                // call allowmanagerPosition so that reentrancyAttacker can close position
                await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, reEntrantProxyWallet, 1)
                //transfer some FXD to reentrancyAttacker contract
                await fathomStablecoin.transfer(reentrancyAttacker.address, WeiPerWad.mul(5), { from: AliceAddress });
                //reentrancyAttack approve reEntrantProxyWallet as spender of FXD
                await reentrancyAttacker.approveWallet(fathomStablecoin.address);
                //reentrancyAttacker tries to call wipeAndUnlockXDC and then all proxyWallet again with fallback function
                //but due to gas limit set in safeTransferETH, the fn call fails.

                    PositionHelper.wipeAndUnlockXDC(
                        reentrancyAttacker,
                        AliceAddress,
                        positionId,
                        WeiPerWad.mul(1),
                        WeiPerWad.mul(2)
                    )

                const [lockedCollateral, debtShare] = await bookKeeper.positions(
                    pools.XDC,
                    positionAddress
                )

                expect(lockedCollateral).to.be.equal(WeiPerWad.mul(10));
                AssertHelpers.assertAlmostEqual(
                    debtShare,
                    WeiPerWad.mul(5)
                )


                
            })
        })
        context("try reentry with ReentrancyAttacker2", () => {
            it("should fail", async () => {
                await simplePriceFeed.setPrice(WeiPerRay, { gasLimit: 1000000 })

                // position 1
                //  a. open a new position
                //  b. lock WXDC
                //  c. mint FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5))

                const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address)
                const positionAddress = await positionManager.positions(positionId)
                
                // call allowmanagerPosition so that reentrancyAttacker can close position
                await PositionHelper.allowManagePosition(aliceProxyWallet, AliceAddress, 1, reEntrantProxyWallet2, 1)
                //transfer some FXD to reentrancyAttacker contract
                await fathomStablecoin.transfer(reentrancyAttacker2.address, WeiPerWad.mul(5), { from: AliceAddress });
                //reentrancyAttack approve reEntrantProxyWallet as spender of FXD
                await reentrancyAttacker2.approveWallet(fathomStablecoin.address);
                //reentrancyAttacker tries to call wipeAndUnlockXDC and then all proxyWallet again with fallback function
                //but due to gas limit set in safeTransferETH, the fn call fails.

                await expect(
                    PositionHelper.wipeAndUnlockXDC(
                        reentrancyAttacker2,
                        AliceAddress,
                        positionId,
                        WeiPerWad.mul(1),
                        WeiPerWad.mul(2)
                    )
                ).to.be.revertedWith("!safeTransferETH")
            })
        })
    })

    describe("#wipeAllAndUnlockXDC", () => {
        context("open position and pay back debt without collateral withdrawl", () => {
            it("should be success", async () => {
                await simplePriceFeed.setPrice(WeiPerRay, { gasLimit: 1000000 })

                // position 1
                //  a. open a new position
                //  b. lock WXDC
                //  c. mint FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5))
                const positionId = await positionManager.ownerLastPositionId(aliceProxyWallet.address)
                const positionAddress = await positionManager.positions(positionId)

                // position 2
                //  a. open a new position
                //  b. lock WXDC
                //  c. mint FXD
                await PositionHelper.openXDCPositionAndDraw(aliceProxyWallet, AliceAddress, pools.XDC, WeiPerWad.mul(10), WeiPerWad.mul(5))

                //  a. repay debt fully for position1
                //  b. alice doesn't unlock any XDC
                //  c. check if the position has the same amount of lockedCollateral
                //  d. check if the position has now debtShare of 0 WAD
                await PositionHelper.wipeAllAndUnlockXDC(
                    aliceProxyWallet,
                    AliceAddress,
                    positionId,
                    0
                )

                const [lockedCollateral, debtShare] = await bookKeeper.positions(
                    pools.XDC,
                    positionAddress
                )

                expect(lockedCollateral).to.be.equal(WeiPerWad.mul(10));
                expect(debtShare).to.be.equal(0);
            })
        })
    })
})
