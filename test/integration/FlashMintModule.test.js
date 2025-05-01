const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { parseEther } = ethers.utils;
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { WeiPerRay, WeiPerRad } = require("../helper/unit");

const { getProxy } = require("../../common/proxies");

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

describe("FlastMintModule", () => {
  // Contracts
  let bookKeeper;
  let USDT;
  let flashMintModule;
  let flashMintArbitrager;
  let fathomStablecoin;
  let router;
  let stableSwapModule;
  let stableSwapModuleWrapper;
  let bookKeeperFlashMintArbitrager;
  let stablecoinAdapter;
  let DeployerAddress;
  let governor;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);
    const { deployer } = await getNamedAccounts();
    DeployerAddress = deployer;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    bookKeeper = await getProxy(proxyFactory, "BookKeeper");
    stableSwapModule = await getProxy(proxyFactory, "StableSwapModule");
    stableSwapModuleWrapper = await getProxy(proxyFactory, "StableSwapModuleWrapper");
    stablecoinAdapter = await getProxy(proxyFactory, "StablecoinAdapter");

    const usdtAddr = await stableSwapModule.token();
    USDT = await ethers.getContractAt("ERC20MintableStableSwap", usdtAddr);

    flashMintModule = await getProxy(proxyFactory, "FlashMintModule");

    fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    const Router = await deployments.get("MockedDexRouter");
    router = await ethers.getContractAt("MockedDexRouter", Router.address);
    flashMintArbitrager = await getProxy(proxyFactory, "FlashMintArbitrager");
    bookKeeperFlashMintArbitrager = await getProxy(proxyFactory, "BookKeeperFlashMintArbitrager");
  });

  describe("#flashLoan", async () => {
    context("receiver doesn't have enough tokens to return the loan + fee", async () => {
      it("should revert", async () => {
        const values = [0, 0, 0, 0];
        const targets = [fathomStablecoin.address, bookKeeper.address, flashMintModule.address, stableSwapModule.address];

        const calldatas = [
          fathomStablecoin.interface.encodeFunctionData("mint", [DeployerAddress, parseEther("3000")]),
          bookKeeper.interface.encodeFunctionData("mintUnbackedStablecoin", [
            stablecoinAdapter.address,
            stablecoinAdapter.address,
            WeiPerRad.mul(3500),
          ]),
          flashMintModule.interface.encodeFunctionData("addToWhitelist", [DeployerAddress]),
          stableSwapModule.interface.encodeFunctionData("addToWhitelist", [flashMintArbitrager.address]),
        ];

        const proposalTx = await governor.propose(targets, values, calldatas, "Set FlashMintModule");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set FlashMintModule"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await USDT.approve(router.address, parseEther("500"));
        await router.deposit(USDT.address, parseEther("500"));
        await expect(
          flashMintModule.flashLoan(
            flashMintArbitrager.address,
            fathomStablecoin.address,
            parseEther("100"),
            ethers.utils.defaultAbiCoder.encode(["address", "address", "address"], [router.address, USDT.address, stableSwapModule.address])
          )
        ).to.be.revertedWith("!safeTransferFrom");
      });
    });

    context("receiver has enough tokens to return the loan + fee", async () => {
      it("should success", async () => {
        const values = [0, 0, 0, 0];
        const targets = [fathomStablecoin.address, bookKeeper.address, flashMintModule.address, stableSwapModule.address];

        const calldatas = [
          fathomStablecoin.interface.encodeFunctionData("mint", [DeployerAddress, parseEther("3500")]),
          bookKeeper.interface.encodeFunctionData("mintUnbackedStablecoin", [
            stablecoinAdapter.address,
            stablecoinAdapter.address,
            WeiPerRad.mul(3500),
          ]),
          flashMintModule.interface.encodeFunctionData("addToWhitelist", [DeployerAddress]),
          stableSwapModule.interface.encodeFunctionData("addToWhitelist", [flashMintArbitrager.address]),
        ];

        const proposalTx = await governor.propose(targets, values, calldatas, "Set FlashMintModule");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set FlashMintModule"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await USDT.approve(router.address, parseEther("500"));
        await router.deposit(USDT.address, parseEther("500"));
        await router.setProfit(true);
        await flashMintModule.flashLoan(
          flashMintArbitrager.address,
          fathomStablecoin.address,
          parseEther("100"),
          ethers.utils.defaultAbiCoder.encode(["address", "address", "address"], [router.address, USDT.address, stableSwapModule.address])
        );

        const profitFromArbitrage = await fathomStablecoin.balanceOf(flashMintArbitrager.address);
        expect(profitFromArbitrage).to.be.equal(parseEther("9.49"));

        const feeCollectedFromFlashMint = await bookKeeper.stablecoin(flashMintModule.address);
        expect(feeCollectedFromFlashMint).to.be.equal(parseEther("0.4").mul(WeiPerRay));
      });
    });

    context("anyone should be able to call flashLoan, no need to whitelist when isDecentralizedState === true", async () => {
      it("should success", async () => {
        await fathomStablecoin.mint(DeployerAddress, parseEther("3500"));
        await bookKeeper.mintUnbackedStablecoin(stablecoinAdapter.address, stablecoinAdapter.address, WeiPerRad.mul(3500));
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        /** No need to addToWhitelist DeployerAddress since everyone can call flashLoan when isDecentralizedState == true */
        // await flashMintModule.addToWhitelist(DeployerAddress);
        await stableSwapModule.addToWhitelist(flashMintArbitrager.address);
        await USDT.approve(router.address, parseEther("500"));
        await router.deposit(USDT.address, parseEther("500"));
        await router.setProfit(true);
        await flashMintModule.flashLoan(
          flashMintArbitrager.address,
          fathomStablecoin.address,
          parseEther("100"),
          ethers.utils.defaultAbiCoder.encode(["address", "address", "address"], [router.address, USDT.address, stableSwapModule.address])
        );

        const profitFromArbitrage = await fathomStablecoin.balanceOf(flashMintArbitrager.address);
        expect(profitFromArbitrage).to.be.equal(parseEther("9.49"));

        const feeCollectedFromFlashMint = await bookKeeper.stablecoin(flashMintModule.address);
        expect(feeCollectedFromFlashMint).to.be.equal(parseEther("0.4").mul(WeiPerRay));
      });
    });
  });

  describe("#bookKeeperFlashLoan", async () => {
    context("receiver doesn't have enough tokens to return the loan + fee", async () => {
      it("should revert", async () => {
        const values = [0, 0, 0, 0];
        const targets = [fathomStablecoin.address, bookKeeper.address, flashMintModule.address, stableSwapModule.address];

        const calldatas = [
          fathomStablecoin.interface.encodeFunctionData("mint", [DeployerAddress, parseEther("3500")]),
          bookKeeper.interface.encodeFunctionData("mintUnbackedStablecoin", [
            stablecoinAdapter.address,
            stablecoinAdapter.address,
            WeiPerRad.mul(3500),
          ]),
          flashMintModule.interface.encodeFunctionData("addToWhitelist", [DeployerAddress]),
          stableSwapModule.interface.encodeFunctionData("addToWhitelist", [bookKeeperFlashMintArbitrager.address]),
        ];

        const proposalTx = await governor.propose(targets, values, calldatas, "Set FlashMintModule");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set FlashMintModule"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await USDT.approve(router.address, parseEther("500"));
        await router.deposit(USDT.address, parseEther("500"));

        await expect(
          flashMintModule.bookKeeperFlashLoan(
            bookKeeperFlashMintArbitrager.address,
            parseEther("100"),
            ethers.utils.defaultAbiCoder.encode(["address", "address", "address"], [router.address, USDT.address, stableSwapModule.address])
          )
        ).to.be.reverted;
      });
    });

    context("receiver has enough tokens to return the loan + fee", async () => {
      it("should success", async () => {
        const values = [0, 0, 0, 0];
        const targets = [fathomStablecoin.address, bookKeeper.address, flashMintModule.address, stableSwapModule.address];

        const calldatas = [
          fathomStablecoin.interface.encodeFunctionData("mint", [DeployerAddress, parseEther("3500")]),
          bookKeeper.interface.encodeFunctionData("mintUnbackedStablecoin", [
            stablecoinAdapter.address,
            stablecoinAdapter.address,
            WeiPerRad.mul(3500),
          ]),
          flashMintModule.interface.encodeFunctionData("addToWhitelist", [DeployerAddress]),
          stableSwapModule.interface.encodeFunctionData("addToWhitelist", [bookKeeperFlashMintArbitrager.address]),
        ];

        const proposalTx = await governor.propose(targets, values, calldatas, "Set FlashMintModule");
        const proposalReceipt = await proposalTx.wait();
        const proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        const descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Set FlashMintModule"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        // Execute
        await governor.execute(targets, values, calldatas, descriptionHash);

        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await USDT.approve(router.address, parseEther("500"));
        await router.deposit(USDT.address, parseEther("500"));
        await router.setProfit(true);

        // Perform flash mint
        await flashMintModule.bookKeeperFlashLoan(
          bookKeeperFlashMintArbitrager.address,
          parseEther("100").mul(WeiPerRay),
          ethers.utils.defaultAbiCoder.encode(["address", "address", "address"], [router.address, USDT.address, stableSwapModule.address])
        );

        const profitFromArbitrage = await fathomStablecoin.balanceOf(bookKeeperFlashMintArbitrager.address);
        expect(profitFromArbitrage).to.be.equal(parseEther("9.49"));

        const feeCollectedFromFlashMint = await bookKeeper.stablecoin(flashMintModule.address);
        expect(feeCollectedFromFlashMint).to.be.equal(parseEther("0.4").mul(WeiPerRay));
      });
    });

    context("anyone should be able to call bookKeeperFlashLoan, no need to whitelist when isDecentralizedState === true", async () => {
      it("should success", async () => {
        await fathomStablecoin.mint(DeployerAddress, parseEther("3500"));
        await bookKeeper.mintUnbackedStablecoin(stablecoinAdapter.address, stablecoinAdapter.address, WeiPerRad.mul(3500));
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        /** No need to addToWhitelist DeployerAddress since everyone can call bookKeeperFlashLoan when isDecentralizedState == true */
        // await flashMintModule.addToWhitelist(DeployerAddress);
        await stableSwapModule.addToWhitelist(bookKeeperFlashMintArbitrager.address);
        await USDT.approve(router.address, parseEther("500"));
        await router.deposit(USDT.address, parseEther("500"));
        await router.setProfit(true);

        // Perform flash mint
        await flashMintModule.bookKeeperFlashLoan(
          bookKeeperFlashMintArbitrager.address,
          parseEther("100").mul(WeiPerRay),
          ethers.utils.defaultAbiCoder.encode(["address", "address", "address"], [router.address, USDT.address, stableSwapModule.address])
        );

        const profitFromArbitrage = await fathomStablecoin.balanceOf(bookKeeperFlashMintArbitrager.address);
        expect(profitFromArbitrage).to.be.equal(parseEther("9.49"));

        const feeCollectedFromFlashMint = await bookKeeper.stablecoin(flashMintModule.address);
        expect(feeCollectedFromFlashMint).to.be.equal(parseEther("0.4").mul(WeiPerRay));
      });
    });
  });
});
