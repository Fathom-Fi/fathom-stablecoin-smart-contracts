const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { getProxy } = require("../../common/proxies");

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

describe("ProxyWallet", () => {
  // Contract
  let proxyWalletRegistry;
  let governor;

  let DeployerAddress;
  let AliceAddress;
  let BobAddress;
  let AddressZero;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);

    const { deployer, allice, bob, a0 } = await getNamedAccounts();
    DeployerAddress = deployer;
    AliceAddress = allice;
    BobAddress = bob;
    AddressZero = a0;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    proxyWalletRegistry = await getProxy(proxyFactory, "ProxyWalletRegistry");
    const values = [0];
    const targets = [proxyWalletRegistry.address];
    const calldatas = [proxyWalletRegistry.interface.encodeFunctionData("setDecentralizedMode", [true])];
    const proposalTx = await governor.propose(targets, values, calldatas, "Set Decentralized Mode");
    const proposalReceipt = await proposalTx.wait();
    const proposalId = proposalReceipt.events[0].args.proposalId;

    // wait for the voting period to pass
    await mine(VOTING_DELAY + 1); // wait for the voting period to pass

    await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

    await mine(VOTING_PERIOD + 1);

    // Queue the TX
    const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set Decentralized Mode"));
    await governor.queue(targets, values, calldatas, descriptionHash);

    await time.increase(MIN_DELAY + 1);
    await mine(1);

    // Execute
    await governor.execute(targets, values, calldatas, descriptionHash);
    // await proxyWalletRegistry.setDecentralizedMode(true);
  });
  describe("#new user create a new proxy wallet", async () => {
    context("alice create a new proxy wallet", async () => {
      it("alice should be able to create a proxy wallet", async () => {
        expect(await proxyWalletRegistry.proxies(AliceAddress)).to.be.equal(AddressZero);

        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress);
        const proxyWalletAliceAddress = await proxyWalletRegistry.proxies(AliceAddress);
        expect(proxyWalletAliceAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsAlice = await ethers.getContractAt("ProxyWallet", proxyWalletAliceAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(AliceAddress);
      });
    });
  });
  describe("#user already has a proxy wallet", async () => {
    context("alice already has a proxy wallet and alice creates a new proxy wallet", async () => {
      it("alice should not be able to create a proxy wallet", async () => {
        expect(await proxyWalletRegistry.proxies(AliceAddress)).to.be.equal(AddressZero);
        // #1 alice create a proxy wallet 1
        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress);
        const proxyWalletAliceAddress = await proxyWalletRegistry.proxies(AliceAddress);
        expect(proxyWalletAliceAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsAlice = await ethers.getContractAt("ProxyWallet", proxyWalletAliceAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(AliceAddress);

        // #2 alice create a proxy wallet 2
        await expect(proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress)).to.be.reverted;
      });
    });
  });
  describe("#user want to change the owner of a proxy wallet", async () => {
    context("alice want to change the owner of a proxy wallet to bob, but bob already has proxy wallet", async () => {
      it("alice should not be able to change the owner of a proxy wallet", async () => {
        // #1 alice create a proxy wallet
        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress);
        const proxyWalletAliceAddress = await proxyWalletRegistry.proxies(AliceAddress);
        expect(proxyWalletAliceAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsAlice = await ethers.getContractAt("ProxyWallet", proxyWalletAliceAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(AliceAddress);

        // #2 bob create a proxy wallet
        await proxyWalletRegistry.connect(provider.getSigner(BobAddress)).build(BobAddress);
        const proxyWalletBobAddress = await proxyWalletRegistry.proxies(BobAddress);
        expect(proxyWalletBobAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsBob = await ethers.getContractAt("ProxyWallet", proxyWalletBobAddress);
        expect(await proxyWalletAsBob.connect(provider.getSigner(BobAddress)).owner()).to.be.equal(BobAddress);

        // #3 alice set bob to owner proxy wallet registry
        await expect(proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).setOwner(BobAddress)).to.be.reverted;
      });
    });
    context("alice only change the owner of a proxy wallet registry", async () => {
      it("alice should not be able to change the owner of a proxy wallet registry", async () => {
        // #1 alice create a proxy wallet
        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress);
        const proxyWalletAliceAddress = await proxyWalletRegistry.proxies(AliceAddress);
        expect(proxyWalletAliceAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsAlice = await ethers.getContractAt("ProxyWallet", proxyWalletAliceAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(AliceAddress);

        // #2 alice set bob to owner proxy wallet registry
        await expect(proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).setOwner(BobAddress)).to.be.reverted;
      });
    });
    context("alice change the owner of a proxy wallet and proxy wallet registry", async () => {
      it("alice should be able to change the owner of a proxy wallet", async () => {
        // #1 alice create a proxy wallet
        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress);
        const proxyWalletAliceAddress = await proxyWalletRegistry.proxies(AliceAddress);
        expect(proxyWalletAliceAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsAlice = await ethers.getContractAt("ProxyWallet", proxyWalletAliceAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(AliceAddress);

        // #2 alice set bob to owner proxy wallet
        await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).setOwner(BobAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(BobAddress);

        // #3 alice set bob to owner proxy wallet registry
        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).setOwner(BobAddress);
        expect(await proxyWalletRegistry.proxies(BobAddress)).to.be.equal(proxyWalletAliceAddress);
        expect(await proxyWalletRegistry.proxies(AliceAddress)).to.be.equal(AddressZero);
      });
    });
  });

  describe("Should fail for empty data", async () => {
    context("Should not be able to execute empty data", async () => {
      it("Should revert for empty data", async () => {
        await proxyWalletRegistry.connect(provider.getSigner(AliceAddress)).build(AliceAddress);
        const proxyWalletAliceAddress = await proxyWalletRegistry.proxies(AliceAddress);
        expect(proxyWalletAliceAddress).to.be.not.equal(AddressZero);
        const proxyWalletAsAlice = await ethers.getContractAt("ProxyWallet", proxyWalletAliceAddress);
        expect(await proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).owner()).to.be.equal(AliceAddress);
        await expect(
          proxyWalletAsAlice.connect(provider.getSigner(AliceAddress)).execute(
            [] //EMPTY DATA
          )
        ).to.be.revertedWith("proxy-wallet-data-required");
      });
    });
  });
});
