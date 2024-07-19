const chai = require('chai');
const { solidity } = require("ethereum-waffle");
chai.use(solidity);
const { expect } = require("chai");

const { DeployerAddress } = require("../../helper/address");
const { loadFixture } = require("../../helper/fixtures");
const { getContract, createMock } = require("../../helper/contracts");
const { WeiPerWad } = require("../../helper/unit")
const { latest } = require('../../helper/time');
const { BigNumber, ethers } = require('ethers');
const { parseUnits } = ethers.utils

const setup = async () => {
    const dexPriceOracle = getContract("MockDexPriceOracle", DeployerAddress);
    const mockedFactory = await createMock("IFathomSwapFactory")
    const mockedPair = await createMock("IFathomSwapPair")
    const mockedToken = await createMock("ERC20Mintable");
    const mockedUSD = await createMock("ERC20Mintable");

    await dexPriceOracle.initialize(mockedFactory.address)

    return { dexPriceOracle, mockedFactory, mockedPair, mockedToken, mockedUSD }
}

xdescribe("DexPriceOracle", () => {
    // Contract
    let dexPriceOracle
    let mockedPair
    let mockedToken
    let mockedUSD
    let mockedFactory

    before(async () => {
        await snapshot.revertToSnapshot();
    })

    beforeEach(async () => {
        ({ dexPriceOracle, mockedFactory, mockedPair, mockedToken, mockedUSD } = await loadFixture(setup));
    })

    describe("#getPrice()", async () => {
        context("same tokens", async () => {
            it("should revert", async () => {
                await expect(dexPriceOracle.getPrice(mockedToken.address, mockedToken.address)).to.be.revertedWith("DexPriceOracle/same-tokens");
            })
        })
        context("price was returned from dex", async () => {
            it("should success", async () => {

                await mockedFactory.mock.getPair.returns(mockedPair.address);
                await mockedToken.mock.decimals.returns(BigNumber.from("18"));
                await mockedUSD.mock.decimals.returns(BigNumber.from("18"));

                if (BigNumber.from(mockedToken.address).lt(BigNumber.from(mockedUSD.address))) {
                    await mockedPair.mock.getReserves.returns(WeiPerWad, WeiPerWad.mul(2), await latest());
                } else {
                    await mockedPair.mock.getReserves.returns(WeiPerWad.mul(2), WeiPerWad, await latest());
                }

                const price0 = await dexPriceOracle.getPrice(mockedToken.address, mockedUSD.address);
                const price1 = await dexPriceOracle.getPrice(mockedUSD.address, mockedToken.address);

                expect(price0[0]).to.be.equal(WeiPerWad.mul(2))
                expect(price1[0]).to.be.equal(WeiPerWad.div(2))
            })
        })
        context("different deciamls", async () => {
            it("should success", async () => {

                await mockedFactory.mock.getPair.returns(mockedPair.address);
                await mockedToken.mock.decimals.returns(BigNumber.from("20"));
                await mockedUSD.mock.decimals.returns(BigNumber.from("6"));

                if (BigNumber.from(mockedToken.address).lt(BigNumber.from(mockedUSD.address))) {
                    await mockedPair.mock.getReserves.returns(parseUnits("1205", 20), parseUnits("49", 6), await latest());
                } else {
                    await mockedPair.mock.getReserves.returns(parseUnits("49", 6), parseUnits("1205", 20), await latest());
                }

                const price0 = await dexPriceOracle.getPrice(mockedToken.address, mockedUSD.address);
                const price1 = await dexPriceOracle.getPrice(mockedUSD.address, mockedToken.address);

                expect(price0[0]).to.be.equal(BigNumber.from("40663900414937759"));
                expect(price1[0]).to.be.equal(BigNumber.from("24591836734693877551"));
            })
        })
    })
})