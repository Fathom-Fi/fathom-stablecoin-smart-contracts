const { ethers, getNamedAccounts } = require("hardhat");
const provider = ethers.provider;
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const { getProxy } = require("../../common/proxies");

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

describe("CollateralTokenAdapter", () => {
  // Contracts
  let collateralTokenAdapter;
  let WXDC;
  let bookKeeper;
  let DeployerAddress;
  let AliceAddress;
  let BobAddress;
  let governor;

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
    collateralTokenAdapter = await getProxy(proxyFactory, "CollateralTokenAdapter");
    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    const _WXDC = await deployments.get("WXDC");
    WXDC = await ethers.getContractAt("WXDC", _WXDC.address);
  });
  describe("#totalShare", async () => {
    context("when all collateral tokens are deposited by deposit function", async () => {
      it("should return the correct net asset valuation", async () => {
        //Alice wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });

        const encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        const proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));

        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(0);
      });
    });

    context("when some one directly transfer collateral tokens to CollateralTokenAdapter", async () => {
      it("should only recognized collateral tokens from deposit function", async () => {
        //Alice wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        const encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        const proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));
        //Bob wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(BobAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(89) });
        await WXDC.connect(provider.getSigner(BobAddress)).transfer(collateralTokenAdapter.address, ethers.utils.parseEther("88"));

        expect(await WXDC.balanceOf(collateralTokenAdapter.address)).to.be.eq(ethers.utils.parseEther("88"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));

        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await WXDC.balanceOf(collateralTokenAdapter.address)).to.be.eq(ethers.utils.parseEther("88"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(0);
      });
    });
  });

  describe("#deposit", async () => {
    context("when CollateralTokenAdapter is not live", async () => {
      it("should revert", async () => {
        /** =========== Cage collateralTokenAdapter =========== */
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("cage");

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Cage");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Cage"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        /** =========== Add to whitelist =========== */
        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [DeployerAddress]);

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await expect(
          collateralTokenAdapter.deposit(
            DeployerAddress,
            ethers.utils.parseEther("1"),
            ethers.utils.defaultAbiCoder.encode(["address"], [DeployerAddress])
          )
        ).to.be.revertedWith("CollateralTokenAdapter/not-live");
      });
    });

    context("when all parameters are valid", async () => {
      it("should work", async () => {
        //Alice wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        // Assuming Alice is the first one to deposit hence no rewards to be harvested yet
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("2"));

        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, 0, ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));

        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        //Bob wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(BobAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(4) });
        await WXDC.connect(provider.getSigner(BobAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("4"));

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [BobAddress]);

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Bob is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .deposit(BobAddress, ethers.utils.parseEther("4"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("5"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("4"));

        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .deposit(BobAddress, 0, ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("5"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("4"));
      });
    });
  });

  describe("#withdraw", async () => {
    context("when withdraw more than what CollateralTokenAdapter staked", async () => {
      it("should revert", async () => {
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        //Alice wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        await expect(
          collateralTokenAdapter
            .connect(provider.getSigner(AliceAddress))
            .withdraw(AliceAddress, ethers.utils.parseEther("100"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]))
        ).to.be.revertedWith("CollateralTokenAdapter/insufficient collateral amount");
      });
    });

    context("when withdraw more than what he staked", async () => {
      it("should revert", async () => {
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [BobAddress]);

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Bob is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await WXDC.connect(provider.getSigner(BobAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(4) });
        await WXDC.connect(provider.getSigner(BobAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("4"));
        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .deposit(BobAddress, ethers.utils.parseEther("4"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

        await expect(
          collateralTokenAdapter
            .connect(provider.getSigner(AliceAddress))
            .withdraw(AliceAddress, ethers.utils.parseEther("2"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]))
        ).to.be.revertedWith("CollateralTokenAdapter/insufficient collateral amount");
      });
    });

    context("when CollateralTokenAdapter is not live", async () => {
      it("should still allow user to withdraw", async () => {
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        // Assuming Alice is the first one to deposit hence no rewards to be harvested yet
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("cage");

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Cage");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Cage"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Cage CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        expect(await collateralTokenAdapter.live()).to.be.eq(0);

        // Now Alice withdraw her position. 4 blocks have been passed.
        // CollateralTokenAdapter is caged, non of FXD has been harvested.
        // Staked collateralTokens have been emergencyWithdraw from FairLaunch.
        // The following conditions must be satisfy:
        // - Alice should get 0 FXD as cage before FXD get harvested.
        // - Alice should get 1 WXDC back.
        let aliceWXDCbefore = await WXDC.balanceOf(AliceAddress);
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));
        let aliceWXDCafter = await WXDC.balanceOf(AliceAddress);

        expect(aliceWXDCafter.sub(aliceWXDCbefore)).to.be.eq(ethers.utils.parseEther("1"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(0);
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("0"));
      });

      it("should still allow user to withdraw with pending rewards (if any)", async () => {
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });

        // Assuming Alice is the first one to deposit hence no rewards to be harvested yet
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        await WXDC.connect(provider.getSigner(BobAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(4) });

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [BobAddress]);

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Bob is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        // Bob join the party with 4 WXDC! 2 Blocks have been passed.
        await WXDC.connect(provider.getSigner(BobAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("4"));
        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .deposit(BobAddress, ethers.utils.parseEther("4"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("5"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("4"));

        // advanceBlock
        await hre.network.provider.send("hardhat_mine", ["0x01"]);

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("cage");

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Cage");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Cage"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Cage CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        expect(await collateralTokenAdapter.live()).to.be.eq(0);

        // Now Alice withdraw her position. Only 200 FXD has been harvested from FairLaunch.
        // CollateralTokenAdapter is caged. Staked collateralTokens have been emergencyWithdraw from FairLaunch.
        // The following conditions must be satisfy:
        // - Alice pending rewards must be 200 FXD
        // - Bob pending rewards must be 0 FXD as all rewards after Bob deposited hasn't been harvested.
        // - Alice should get 180 (200 - 10%) FXD that is harvested before cage (when Bob deposited)
        // - Alice should get 1 WXDC back.
        // - treasury account should get 20 FXD.

        let aliceWXDCbefore = await WXDC.balanceOf(AliceAddress);
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));
        let aliceWXDCafter = await WXDC.balanceOf(AliceAddress);

        expect(aliceWXDCafter.sub(aliceWXDCbefore)).to.be.eq(ethers.utils.parseEther("1"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("4"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("0"));

        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("4"));

        let bobWXDCbefore = await WXDC.balanceOf(BobAddress);
        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .withdraw(BobAddress, ethers.utils.parseEther("4"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));
        let bobWXDCafter = await WXDC.balanceOf(BobAddress);

        expect(bobWXDCafter.sub(bobWXDCbefore)).to.be.eq(ethers.utils.parseEther("4"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(0);
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("0"));

        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("0"));
      });
    });

    context("when all parameters are valid", async () => {
      it("should work", async () => {
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        //Alice wraps XDC to WXDC
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        // Assuming Alice is the first one to deposit hence no rewards to be harvested yet
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        // Now Alice withdraw her position. 1 block has been passed, hence Alice should get 90 (100 - 10%) FXD, treasury account should get 10 FXD.
        let aliceWXDCbefore = await WXDC.balanceOf(AliceAddress);
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));
        let aliceWXDCafter = await WXDC.balanceOf(AliceAddress);

        expect(aliceWXDCafter.sub(aliceWXDCbefore)).to.be.eq(ethers.utils.parseEther("1"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(0);
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("0"));
      });
    });
    context("when bob withdraw collateral to alice", async () => {
      context("when bob doesn't has collateral", () => {
        it("should be revert", async () => {
          let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

          let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
          let proposalReceipt = await proposalTx.wait();
          let proposalId = proposalReceipt.events[0].args.proposalId;

          // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
          await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
          await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
          await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
          // Assuming Alice is the first one to deposit hence no rewards to be harvested yet
          await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
          await collateralTokenAdapter
            .connect(provider.getSigner(AliceAddress))
            .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

          encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [BobAddress]);

          proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
          proposalReceipt = await proposalTx.wait();
          proposalId = proposalReceipt.events[0].args.proposalId;

          // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
          await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          // Bob is whiteListed to directly call deposit function on CollateralTokenAdapter
          await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
          //checking with Subik-ji
          let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();

          expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

          await expect(
            collateralTokenAdapter
              .connect(provider.getSigner(BobAddress))
              .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]))
          ).to.be.revertedWith("CollateralTokenAdapter/insufficient collateral amount");
        });
      });
      context("when bob has collateral", async () => {
        it("should be able to call withdraw", async () => {
          let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

          let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
          let proposalReceipt = await proposalTx.wait();
          let proposalId = proposalReceipt.events[0].args.proposalId;

          // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
          await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
          await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
          await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
          await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
          await collateralTokenAdapter
            .connect(provider.getSigner(AliceAddress))
            .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

          expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
          let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
          expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

          encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [BobAddress]);

          proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
          proposalReceipt = await proposalTx.wait();
          proposalId = proposalReceipt.events[0].args.proposalId;

          // wait for the voting period to pass
          await mine(VOTING_DELAY + 1); // wait for the voting period to pass

          await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

          await mine(VOTING_PERIOD + 1);

          // Queue the TX
          descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
          await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

          await time.increase(MIN_DELAY + 1);
          await mine(1);

          // Execute
          // Bob is whiteListed to directly call deposit function on CollateralTokenAdapter
          await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
          await WXDC.connect(provider.getSigner(BobAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
          await WXDC.connect(provider.getSigner(BobAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
          await collateralTokenAdapter
            .connect(provider.getSigner(BobAddress))
            .deposit(BobAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

          let aliceWXDCbefore = await WXDC.balanceOf(AliceAddress);
          let bobWXDCbefore = await WXDC.balanceOf(BobAddress);
          await collateralTokenAdapter
            .connect(provider.getSigner(BobAddress))
            .withdraw(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));
          let aliceWXDCafter = await WXDC.balanceOf(AliceAddress);
          let bobWXDCafter = await WXDC.balanceOf(BobAddress);

          expect(aliceWXDCafter.sub(aliceWXDCbefore)).to.be.eq(ethers.utils.parseEther("1"));
          expect(bobWXDCafter.sub(bobWXDCbefore)).to.be.eq(ethers.utils.parseEther("0"));
        });
      });
    });
  });

  describe("#emergencyWithdraw", async () => {
    context("when CollateralTokenAdapter is not live", async () => {
      it("should allow users to exit with emergencyWithdraw and normal withdraw", async () => {
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(2) });
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        // Assuming Alice is the first one to deposit hence no rewards to be harvested yet
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        await WXDC.connect(provider.getSigner(BobAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(4) });

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [BobAddress]);

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Bob is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        // Bob join the party with 4 WXDC! 2 Blocks have been passed.
        await WXDC.connect(provider.getSigner(BobAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("4"));
        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .deposit(BobAddress, ethers.utils.parseEther("4"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("5"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("4"));

        // Move 1 block so CollateralTokenAdapter make 100 FXD. However this portion
        // won't be added as CollateralTokenAdapter cage before it get harvested.
        await hre.network.provider.send("hardhat_mine", ["0x01"]);

        encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("cage");

        proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Cage");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Cage"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Cage CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        expect(await collateralTokenAdapter.live()).to.be.eq(0);

        // Alice panic and decided to emergencyWithdraw.
        // The following states are expected:
        // - Alice should get 1 WXDC back.
        let aliceWXDCbefore = await WXDC.balanceOf(AliceAddress);
        await collateralTokenAdapter.connect(provider.getSigner(AliceAddress)).emergencyWithdraw(AliceAddress);
        let aliceWXDCafter = await WXDC.balanceOf(AliceAddress);

        expect(aliceWXDCafter.sub(aliceWXDCbefore)).to.be.eq(ethers.utils.parseEther("1"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("4"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("0"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("4"));

        // Bob chose to withdraw normal.
        // But in real life situation, Bob would not be whitelisted so that he can
        // directly deposit and withdraw WXDC via CollateralTokenAdapter.
        // The following states are expected:
        // - Bob should get his 4 WXDC back
        let bobWXDCbefore = await WXDC.balanceOf(BobAddress);
        await collateralTokenAdapter
          .connect(provider.getSigner(BobAddress))
          .withdraw(BobAddress, ethers.utils.parseEther("4"), ethers.utils.defaultAbiCoder.encode(["address"], [BobAddress]));
        let bobWXDCafter = await WXDC.balanceOf(BobAddress);

        expect(bobWXDCafter.sub(bobWXDCbefore)).to.be.eq(ethers.utils.parseEther("4"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(0);
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("0"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, BobAddress)).to.be.eq(ethers.utils.parseEther("0"));
      });
    });

    context("when all states are normal", async () => {
      it("can call emergencyWithdraw but the state will stay the same", async () => {
        await WXDC.connect(provider.getSigner(AliceAddress)).deposit({ value: ethers.constants.WeiPerEther.mul(1) });
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("addToWhitelist", [AliceAddress]);

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Add to whitelist");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Add to whitelist"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        //Alice is whiteListed to directly call deposit function on CollateralTokenAdapter
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        await WXDC.connect(provider.getSigner(AliceAddress)).approve(collateralTokenAdapter.address, ethers.utils.parseEther("1"));
        await collateralTokenAdapter
          .connect(provider.getSigner(AliceAddress))
          .deposit(AliceAddress, ethers.utils.parseEther("1"), ethers.utils.defaultAbiCoder.encode(["address"], [AliceAddress]));

        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        let collateralPoolIdFromAdapter = await collateralTokenAdapter.collateralPoolId();
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));

        // Alice feels in-secure, so she does emergencyWithdraw
        // However, the collateralTokenAdapter is not uncaged, therefore
        // - Alice cannot get here 1 WXDC back
        // - Alice's state stays the same.
        let aliceWXDCbefore = await WXDC.balanceOf(AliceAddress);
        await collateralTokenAdapter.connect(provider.getSigner(AliceAddress)).emergencyWithdraw(AliceAddress);
        let aliceWXDCafter = await WXDC.balanceOf(AliceAddress);

        expect(aliceWXDCafter.sub(aliceWXDCbefore)).to.be.eq(ethers.utils.parseEther("0"));
        expect(await collateralTokenAdapter.totalShare()).to.be.eq(ethers.utils.parseEther("1"));
        expect(await bookKeeper.collateralToken(collateralPoolIdFromAdapter, AliceAddress)).to.be.eq(ethers.utils.parseEther("1"));
      });
    });
  });

  describe("#cage/#uncage", async () => {
    context("when whitelist cage", async () => {
      it("should put CollateralTokenAdapter live = 0", async () => {
        let encodedFunctionCall = collateralTokenAdapter.interface.encodeFunctionData("cage");

        let proposalTx = await governor.propose([collateralTokenAdapter.address], [0], [encodedFunctionCall], "Cage");
        let proposalReceipt = await proposalTx.wait();
        let proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        let descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Cage"));
        await governor.queue([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        // Cage
        await governor.execute([collateralTokenAdapter.address], [0], [encodedFunctionCall], descriptionHash);
        expect(await collateralTokenAdapter.live()).to.be.eq(0);
      });
    });

    context("when caller not owner role cage", async () => {
      context("when assumptions still valid", async () => {
        it("should revert", async () => {
          await expect(collateralTokenAdapter.connect(provider.getSigner(AliceAddress)).cage()).to.be.revertedWith(
            "CollateralTokenAdapter/not-authorized"
          );
        });
      });
    });
  });
});
