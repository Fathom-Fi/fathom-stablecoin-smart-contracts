const chai = require('chai');
const { BigNumber } = require("ethers");

const { solidity } = require("ethereum-waffle");
const { formatBytes32String } = require("ethers/lib/utils");

chai.use(solidity);

const { expect } = chai
const COLLATERAL_POOL_ID = formatBytes32String("WXDC")
const { DeployerAddress } = require("../helper/address");

describe("CollateralTokenAdapter", () => {
    // Contracts
    let collateralTokenAdapterFactory
    let collateralTokenAdapter
    let bookKeeper
    let WXDC
    let shield
    let fathomToken
    let fairLaunch

    beforeEach(async () => {
        await snapshot.revertToSnapshot();

        bookKeeper = await artifacts.initializeInterfaceAt("BookKeeper", "BookKeeper");
        fathomToken = await artifacts.initializeInterfaceAt("FathomToken", "FathomToken");
        fairLaunch = await artifacts.initializeInterfaceAt("FairLaunch", "FairLaunch");
        shield = await artifacts.initializeInterfaceAt("Shield", "Shield");
        WXDC = await artifacts.initializeInterfaceAt("WXDC", "WXDC");
        collateralTokenAdapterFactory = await artifacts.initializeInterfaceAt("CollateralTokenAdapterFactory", "CollateralTokenAdapterFactory");
        const collateralTokenAdapterAddress = await collateralTokenAdapterFactory.getAdapter(COLLATERAL_POOL_ID)
        collateralTokenAdapter = await artifacts.initializeInterfaceAt("CollateralTokenAdapter", collateralTokenAdapterAddress);
    })

    describe("#createAdapter", async () => {
        context("when collateralToken not match with FairLaunch", async () => {
            it("should revert", async () => {
                await expect(
                    collateralTokenAdapterFactory.createAdapter(
                        bookKeeper.address,
                        COLLATERAL_POOL_ID,
                        fathomToken.address,
                        fathomToken.address,
                        fairLaunch.address,
                        0,
                        shield.address,
                        DeployerAddress,
                        BigNumber.from(1000),
                        DeployerAddress,
                        DeployerAddress,
                        { gasLimit: 5000000 }
                    )
                ).to.be.revertedWith("CollateralTokenAdapter/collateralToken-not-match")
            })
        })

        context("when rewardToken not match with FairLaunch", async () => {
            it("should revert", async () => {
                await expect(
                    collateralTokenAdapterFactory.createAdapter(
                        bookKeeper.address,
                        COLLATERAL_POOL_ID,
                        WXDC.address,
                        WXDC.address,
                        fairLaunch.address,
                        0,
                        shield.address,
                        DeployerAddress,
                        BigNumber.from(1000),
                        DeployerAddress,
                        DeployerAddress,
                        { gasLimit: 5000000 }
                    )
                ).to.be.revertedWith("CollateralTokenAdapter/reward-token-not-match")
            })
        })

        context("when shield not match with FairLaunch", async () => {
            it("should revert", async () => {
                await expect(
                    collateralTokenAdapterFactory.createAdapter(
                        bookKeeper.address,
                        COLLATERAL_POOL_ID,
                        WXDC.address,
                        fathomToken.address,
                        fairLaunch.address,
                        0,
                        DeployerAddress,
                        DeployerAddress,
                        BigNumber.from(1000),
                        DeployerAddress,
                        DeployerAddress,
                        { gasLimit: 5000000 }
                    )
                ).to.be.revertedWith("CollateralTokenAdapter/shield-not-match")
            })
        })

        context("when timelock not match with FairLaunch", async () => {
            it("should revert", async () => {
                await expect(
                    collateralTokenAdapterFactory.createAdapter(
                        bookKeeper.address,
                        COLLATERAL_POOL_ID,
                        WXDC.address,
                        fathomToken.address,
                        fairLaunch.address,
                        0,
                        shield.address,
                        shield.address,
                        BigNumber.from(1000),
                        DeployerAddress,
                        DeployerAddress,
                        { gasLimit: 5000000 }
                    )
                ).to.be.revertedWith("CollateralTokenAdapter/timelock-not-match")
            })
        })

        context("when all assumptions are correct", async () => {
            it("should initalized correctly", async () => {
                expect(await collateralTokenAdapter.bookKeeper()).to.be.eq(bookKeeper.address)
                expect(await collateralTokenAdapter.collateralPoolId()).to.be.eq(COLLATERAL_POOL_ID)
                expect(await collateralTokenAdapter.collateralToken()).to.be.eq(WXDC.address)
                expect(await collateralTokenAdapter.fairlaunch()).to.be.eq(fairLaunch.address)
                expect(await collateralTokenAdapter.pid()).to.be.eq(0)
                expect(await collateralTokenAdapter.shield()).to.be.eq(shield.address)
                expect(await collateralTokenAdapter.timelock()).to.be.eq(DeployerAddress)
                expect(await collateralTokenAdapter.decimals()).to.be.eq(18)
            })
        })
    })
})
