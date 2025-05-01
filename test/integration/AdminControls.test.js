const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { getProxy } = require("../../common/proxies");
const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

describe("AdminControls", () => {
  // Contract
  let adminControls;
  let positionManager;
  let bookKeeper;
  let liquidationEngine;
  let systemDebtEngine;
  let priceOracle;
  let stablecoinAdapter;
  let stableSwapModule;
  let flashMintModule;
  let governor;
  let DeployerAddress;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);
    const { deployer } = await getNamedAccounts();
    DeployerAddress = deployer;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    adminControls = await getProxy(proxyFactory, "AdminControls");
    liquidationEngine = await getProxy(proxyFactory, "LiquidationEngine");
    positionManager = await getProxy(proxyFactory, "PositionManager");
    stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");
    systemDebtEngine = await getProxy(proxyFactory, "SystemDebtEngine");
    priceOracle = await getProxy(proxyFactory, "PriceOracle");
    stableSwapModule = await getProxy(proxyFactory, "StableSwapModule");
    flashMintModule = await getProxy(proxyFactory, "FlashMintModule");
    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
  });

  describe("#pause", () => {
    context("pause protocol", () => {
      it("protocol contracts should be paused", async () => {
        const encodedFunctionCall = adminControls.interface.encodeFunctionData("pauseProtocol");

        const proposalTx = await governor.propose([adminControls.address], [0], [encodedFunctionCall], "Pause protocol");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Pause protocol"));
        await governor.queue([adminControls.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute([adminControls.address], [0], [encodedFunctionCall], descriptionHash);

        expect(await bookKeeper.paused()).to.be.equal(true);
        expect(await liquidationEngine.paused()).to.be.equal(true);
        expect(await positionManager.paused()).to.be.equal(true);
        expect(await systemDebtEngine.paused()).to.be.equal(true);
        expect(await stablecoinAdapter.paused()).to.be.equal(true);
        expect(await priceOracle.paused()).to.be.equal(true);
        expect(await flashMintModule.paused()).to.be.equal(true);
      });
    });
  });
  describe("#unpause", () => {
    context("unpause protocol", () => {
      it("protocol contracts should be unpaused", async () => {
        /** =============== PAUSE PROTOCOL ===================== */
        const encodedFunctionCall = adminControls.interface.encodeFunctionData("pauseProtocol");

        const proposalTx = await governor.propose([adminControls.address], [0], [encodedFunctionCall], "Pause protocol");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Pause protocol"));
        await governor.queue([adminControls.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute([adminControls.address], [0], [encodedFunctionCall], descriptionHash);

        /** =============== UNPAUSE PROTOCOL ==================== */
        const encodedFunctionCallU = adminControls.interface.encodeFunctionData("unpauseProtocol");

        const proposalTxU = await governor.propose([adminControls.address], [0], [encodedFunctionCallU], "Unpause protocol");
        const proposalReceiptU = await proposalTxU.wait();
        const proposalIdU = proposalReceiptU.events[0].args.proposalId;

        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalIdU, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHashU = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Unpause protocol"));
        await governor.queue([adminControls.address], [0], [encodedFunctionCallU], descriptionHashU);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute([adminControls.address], [0], [encodedFunctionCallU], descriptionHashU);

        expect(await bookKeeper.paused()).to.be.equal(false);
        expect(await liquidationEngine.paused()).to.be.equal(false);
        expect(await positionManager.paused()).to.be.equal(false);
        expect(await systemDebtEngine.paused()).to.be.equal(false);
        expect(await stablecoinAdapter.paused()).to.be.equal(false);
        expect(await priceOracle.paused()).to.be.equal(false);
        expect(await flashMintModule.paused()).to.be.equal(false);
      });
    });
  });
});
