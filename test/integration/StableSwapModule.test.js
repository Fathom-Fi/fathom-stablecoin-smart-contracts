const { ethers } = require("hardhat");
const provider = ethers.provider;
const { expect } = require("chai");
const { BigNumber } = ethers;
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");

const { getProxy } = require("../../common/proxies");
const WeiPerSixDecimals = BigNumber.from(`1${"0".repeat(6)}`);

const TO_DEPOSIT = ethers.utils.parseEther("10000000");
const TO_MINT = ethers.utils.parseEther("20000000");
const TWENTY_PERCENT_OF_TO_DEPOSIT = ethers.utils.parseEther("4000000"); //20Million * 20% = 400k
const THIRTY_PERCENT_OF_TO_DEPOSIT = ethers.utils.parseEther("6000000");
const ONE_PERCENT_OF_TOTAL_DEPOSIT = ethers.utils.parseEther("200000");
const FOURTY_PERCENT_OF_TO_DEPOSIT = ethers.utils.parseEther("8000000");
const ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS = WeiPerSixDecimals.mul(200000);

const MIN_DELAY = 3600; // 1 hour
const VOTING_PERIOD = 50400; // This is how long voting lasts, 1 week
const VOTING_DELAY = 1; // How many blocks till a proposal vote becomes active
const VOTE_WAY = 1;

//why this divider:
//right now fee is 0.001
//so for ONE_PERCENT_OF_TOTAL_DEPOSIT = 200000, fee = 200
//so, totalValueDeposited will be decreased by 200 each time we swap to account for fees
//ie. for first swap it will reduce from 200,000,000 to 199,999,800
//for second swap it will reduce from 199,999,800 to 199,999,600
//so, taking One percent of total Deposit = 199,999,800 * 0.01 = 199998 after first swap
//therfore, we divide by 100000 (onehundred thousand)in each swap because we want to take 1% of total deposit
//ie, 200000 * 1e18 - 200000 * 1e18 / 100000 =  =~ 199998 ether
//but dividing by 1000(thousand) so that we account for previous swaps fees
const DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT = BigNumber.from("1000");

describe("StableSwapModule", () => {
  // Contracts
  let USDT;
  let stableSwapModule;
  let fathomStablecoin;
  let stableSwapModuleWrapper;
  let stableswapMultipleSwapsMock;
  let accounts;
  let DeployerAddress;
  let governor;

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);
    const { deployer } = await getNamedAccounts();
    accounts = await ethers.getSigners();
    DeployerAddress = deployer;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

    const Governor = await deployments.get("ProtocolGovernor");
    governor = await ethers.getContractAt("ProtocolGovernor", Governor.address);

    const StableswapMultipleSwapsMock = await deployments.get("StableswapMultipleSwapsMock");
    stableswapMultipleSwapsMock = await ethers.getContractAt("StableswapMultipleSwapsMock", StableswapMultipleSwapsMock.address);

    stableSwapModule = await getProxy(proxyFactory, "StableSwapModule");
    fathomStablecoin = await getProxy(proxyFactory, "FathomStablecoin");
    stableSwapModuleWrapper = await getProxy(proxyFactory, "StableSwapModuleWrapper");

    const usdtAddr = await stableSwapModule.token();
    USDT = await ethers.getContractAt("ERC20Mintable", usdtAddr);

    await USDT.approve(stableSwapModuleWrapper.address, ethers.constants.MaxUint256);
    await fathomStablecoin.approve(stableSwapModuleWrapper.address, ethers.constants.MaxUint256);

    await USDT.mint(DeployerAddress, TO_DEPOSIT);
    await fathomStablecoin.mint(DeployerAddress, TO_DEPOSIT);

    await stableSwapModuleWrapper.depositTokens(TO_DEPOSIT);

    await USDT.approve(stableSwapModule.address, ethers.constants.MaxUint256);
    await fathomStablecoin.approve(stableSwapModule.address, ethers.constants.MaxUint256);
    await USDT.mint(DeployerAddress, TO_MINT);
    await fathomStablecoin.mint(DeployerAddress, TO_MINT);
  });

  describe("#swapTokenToStablecoin", async () => {
    context("swap USDT to FXD", async () => {
      it("should success", async () => {
        const beforeBalanceOfStablecoin = await fathomStablecoin.balanceOf(DeployerAddress);
        const beforeBalanceOfUSDT = await USDT.balanceOf(DeployerAddress);
        const FIVE_HUNDRED_THOUSAND_SIX_DECIMALS = WeiPerSixDecimals.mul(500000);
        await stableSwapModule.swapTokenToStablecoin(DeployerAddress, FIVE_HUNDRED_THOUSAND_SIX_DECIMALS);
        const afterBalanceOfStablecoin = await fathomStablecoin.balanceOf(DeployerAddress);
        const afterBalanceOfUSDT = await USDT.balanceOf(DeployerAddress);

        // 500000 -> from swap, -ve 500 -> from fee. Total balance = 500000-500 = 499500
        expect(afterBalanceOfStablecoin.sub(beforeBalanceOfStablecoin)).to.be.equal(ethers.utils.parseEther("499500"));
        //-ve 500000 -> from swap. Total Balance = 500000
        expect(beforeBalanceOfUSDT.sub(afterBalanceOfUSDT)).to.be.equal(FIVE_HUNDRED_THOUSAND_SIX_DECIMALS);
      });
    });

    context("swap USDT to FXD", async () => {
      it("should success", async () => {
        const beforeBalanceOfStablecoin = await fathomStablecoin.balanceOf(DeployerAddress);
        const beforeBalanceOfUSDT = await USDT.balanceOf(DeployerAddress);
        const ONE_MILLION_SIX_DECIMALS = WeiPerSixDecimals.mul(1000000);

        await stableSwapModule.swapTokenToStablecoin(DeployerAddress, ONE_MILLION_SIX_DECIMALS);
        const afterBalanceOfStablecoin = await fathomStablecoin.balanceOf(DeployerAddress);
        const afterBalanceOfUSDT = await USDT.balanceOf(DeployerAddress);

        // 1000000 -> from swap, -ve 500-> from fee. Total balance = 1000000 - 1000 = 999000
        expect(afterBalanceOfStablecoin.sub(beforeBalanceOfStablecoin)).to.be.equal(ethers.utils.parseEther("999000"));
        // -ve 1000000 -> from swap. Total Balance = 1000000
        expect(beforeBalanceOfUSDT.sub(afterBalanceOfUSDT)).to.be.equal(ONE_MILLION_SIX_DECIMALS);
      });
    });
  });

  describe("#swapStablecoinToToken", async () => {
    context("collateral not enough", async () => {
      it("should SWAP", async () => {
        const beforeBalanceOfStablecoin = await fathomStablecoin.balanceOf(DeployerAddress);
        const beforeBalanceOfUSDT = await USDT.balanceOf(DeployerAddress);

        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ethers.utils.parseEther("1000000"));
        const afterBalanceOfStablecoin = await fathomStablecoin.balanceOf(DeployerAddress);
        const afterBalanceOfUSDT = await USDT.balanceOf(DeployerAddress);
        expect(beforeBalanceOfStablecoin.sub(afterBalanceOfStablecoin)).to.be.equal(ethers.utils.parseEther("1000000"));
        // 1000000 -> from swap, -ve 500-> from fee. Total balance = 1000000 - 1000 = 999000
        expect(afterBalanceOfUSDT.sub(beforeBalanceOfUSDT)).to.be.equal(WeiPerSixDecimals.mul(999000));
      });
    });

    context("swap FXD to USDT", async () => {
      it("should success", async () => {
        // Mint 1000 USDT to deployer

        await stableSwapModule.swapTokenToStablecoin(DeployerAddress, WeiPerSixDecimals.mul(1000));
        // Swap 998 FXD to USDT
        await fathomStablecoin.approve(stableSwapModule.address, ethers.constants.MaxUint256);
        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ethers.utils.parseEther("998"));
      });
    });
  });

  describe("#addToWhitelist", async () => {
    context("add to whitelist and check it should swap", async () => {
      it("should swapStablecoinToToken", async () => {
        const whitelistAccount = accounts[2].address;
        await fathomStablecoin.connect(provider.getSigner(whitelistAccount)).approve(stableSwapModule.address, ethers.constants.MaxUint256);
        await fathomStablecoin.mint(whitelistAccount, TO_MINT);

        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("addToWhitelist", [whitelistAccount])];
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
        // await stableSwapModule.addToWhitelist(whitelistAccount);

        const beforeBalanceOfStablecoin = await fathomStablecoin.balanceOf(whitelistAccount);
        const beforeBalanceOfUSDT = await USDT.balanceOf(whitelistAccount);

        await stableSwapModule
          .connect(provider.getSigner(whitelistAccount))
          .swapStablecoinToToken(whitelistAccount, ethers.utils.parseEther("1000000"));
        const afterBalanceOfStablecoin = await fathomStablecoin.balanceOf(whitelistAccount);
        const afterBalanceOfUSDT = await USDT.balanceOf(whitelistAccount);
        expect(beforeBalanceOfStablecoin.sub(afterBalanceOfStablecoin)).to.be.equal(ethers.utils.parseEther("1000000"));
        // 1000000 -> from swap, -ve 500-> from fee. Total balance = 1000000 - 1000 = 999000
        expect(afterBalanceOfUSDT.sub(beforeBalanceOfUSDT)).to.be.equal(WeiPerSixDecimals.mul(999000));
      });
    });

    context("add to whitelist and check it should swap", async () => {
      it("should swapTokenToStablecoin", async () => {
        const whitelistAccount = accounts[2].address;
        await USDT.connect(provider.getSigner(whitelistAccount)).approve(stableSwapModule.address, ethers.constants.MaxUint256);
        await USDT.mint(whitelistAccount, TO_MINT);
        await fathomStablecoin.mint(whitelistAccount, TO_MINT);

        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("addToWhitelist", [whitelistAccount])];
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
        // await stableSwapModule.addToWhitelist(whitelistAccount);

        await stableSwapModule.connect(provider.getSigner(whitelistAccount)).swapTokenToStablecoin(whitelistAccount, WeiPerSixDecimals.mul(1000000));
      });
    });
  });

  describe("#removeFromWhitelist", async () => {
    context("add to whitelist and check it should swap and again remove from whitelist and check for revert", async () => {
      it("should swapStablecoinToToken and revert", async () => {
        const whitelistAccount = accounts[2].address;
        await fathomStablecoin.connect(provider.getSigner(whitelistAccount)).approve(stableSwapModule.address, ethers.constants.MaxUint256);
        await fathomStablecoin.mint(whitelistAccount, TO_MINT);

        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("addToWhitelist", [whitelistAccount])];
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
        // await stableSwapModule.addToWhitelist(whitelistAccount);
        await stableSwapModule
          .connect(provider.getSigner(whitelistAccount))
          .swapStablecoinToToken(whitelistAccount, ethers.utils.parseEther("1000000"));

        calldatas = [stableSwapModule.interface.encodeFunctionData("removeFromWhitelist", [whitelistAccount])];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await stableSwapModule.removeFromWhitelist(whitelistAccount);
        await expect(
          stableSwapModule.connect(provider.getSigner(whitelistAccount)).swapStablecoinToToken(whitelistAccount, ethers.utils.parseEther("1000000"))
        ).to.be.revertedWith("user-not-whitelisted");
      });
    });

    context("add to whitelist and check it should swap and again remove from whitelist and check for revert", async () => {
      it("should swapTokenToStablecoin and revert", async () => {
        const whitelistAccount = accounts[2].address;
        await USDT.connect(provider.getSigner(whitelistAccount)).approve(stableSwapModule.address, ethers.constants.MaxUint256);
        await USDT.mint(whitelistAccount, TO_MINT);
        await fathomStablecoin.mint(whitelistAccount, TO_MINT);

        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("addToWhitelist", [whitelistAccount])];
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
        // await stableSwapModule.addToWhitelist(whitelistAccount);

        await stableSwapModule.connect(provider.getSigner(whitelistAccount)).swapTokenToStablecoin(whitelistAccount, WeiPerSixDecimals.mul(1000000));

        calldatas = [stableSwapModule.interface.encodeFunctionData("removeFromWhitelist", [whitelistAccount])];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await stableSwapModule.removeFromWhitelist(whitelistAccount);
        await expect(
          stableSwapModule.connect(provider.getSigner(whitelistAccount)).swapTokenToStablecoin(whitelistAccount, WeiPerSixDecimals.mul(1000000))
        ).to.be.revertedWith("user-not-whitelisted");
      });
    });
  });

  describe("#dailyLimitCheck", async () => {
    context("check for daily limit", async () => {
      it("Should swap tokens and revert when dailyswap limit is reached", async () => {
        //first swap which takes all the allowance

        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);

        console.log("Swapping twenty times to check for DailyLimit Cross");
        let numberOfSwaps = 0;
        for (let i = 0; i < 10; i++) {
          console.log("Swapping Token to Stablecoin - No...........", i + 1);
          //div by 1000 so that single swap limit is not reached
          await stableSwapModule.swapTokenToStablecoin(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          );
          //increase block time so that a block is mined before swapping
          await time.increase(1);
          numberOfSwaps++;
        }

        for (let i = 0; i < 10; i++) {
          console.log("Swapping Stablecion to Token - No...........", i + 1);
          await stableSwapModule.swapStablecoinToToken(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          );
          //increase block time so that a block is mined before swapping
          await time.increase(1);
          numberOfSwaps++;
        }
        //revert because it exceed allowance

        await expect(
          stableSwapModule.swapTokenToStablecoin(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          )
        ).to.be.revertedWith("_updateAndCheckDailyLimit/daily-limit-exceeded");
        await time.increase(1);
        await expect(
          stableSwapModule.swapStablecoinToToken(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          )
        ).to.be.revertedWith("_updateAndCheckDailyLimit/daily-limit-exceeded");
        await time.increase(1);
        const ONE_DAY = 86400;
        await time.increase(ONE_DAY + 20);
        //again swap after increasing timestamp
        //should succeed
        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT));

        calldatas = [stableSwapModule.interface.encodeFunctionData("initializeFeesAfterUpgrade")];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await stableSwapModule.initializeFeesAfterUpgrade();

        proposalTx = await governor.propose(targets, values, calldatas, "Initialize again");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Initialize again"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await expect(governor.execute(targets, values, calldatas, descriptionHash)).to.be.revertedWith(
          "TimelockController: underlying transaction reverted"
        );
      });
    });

    context("check for daily limit - depositToken", async () => {
      it("Should update dailyLimit on depositing more token", async () => {
        await time.increase(1);

        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);

        await stableSwapModule.swapTokenToStablecoin(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS);
        await time.increase(1);
        await stableSwapModuleWrapper.depositTokens(TO_DEPOSIT);
        //Why GreaterThanOrEqual? Because there is one swap already done which incurs fee so total pool has increased
        await time.increase(1);
        const remainingDailySwapAmount = await stableSwapModule.remainingDailySwapAmount();
        expect(remainingDailySwapAmount).to.be.gte(
          FOURTY_PERCENT_OF_TO_DEPOSIT.sub(FOURTY_PERCENT_OF_TO_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );
      });
    });

    context("check for daily limit - setDailySwapLimitNumerator", async () => {
      it("Should update dailyLimit on depositing more token", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        await stableSwapModuleWrapper.depositTokens(TO_DEPOSIT);
        await stableSwapModule.swapTokenToStablecoin(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS);
        calldatas = [stableSwapModule.interface.encodeFunctionData("setDailySwapLimitNumerator", [3000])];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await stableSwapModule.setDailySwapLimitNumerator(3000);
        //Why GreaterThanOrEqual? Because there is one swap already done which incurs fee so total pool has increased
        const remainingDailySwapAmount = await stableSwapModule.remainingDailySwapAmount();
        expect(remainingDailySwapAmount).to.be.gte(THIRTY_PERCENT_OF_TO_DEPOSIT);
      });
    });
  });

  describe("#singleSwapLimitCheck", async () => {
    context("check for daily limit", async () => {
      it("Should revert when SingleSwap Limit is reached", async () => {
        //first swap which takes all the allowance
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        await expect(stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT.add(1))).to.be.revertedWith(
          "_checkSingleSwapLimit/single-swap-exceeds-limit"
        );
      });
    });
  });

  describe("#singleBlockLimitCheck", async () => {
    context("check for block limit", async () => {
      it("Should revert when number of swaps per block limit is reached", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);

        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT);
        //this reverts because one user can swap only once in two blocks and we have already done one swap
        await expect(
          stableSwapModule.swapTokenToStablecoin(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          )
        ).to.be.revertedWith("_updateAndCheckNumberOfSwapsInBlocksPerLimit/swap-limit-exceeded");
      });
    });
  });

  describe("#checkForDifferentBlockLimitsSet", async () => {
    context("check for block limit", async () => {
      it("Should revert when SingleSwap Limit is reached", async () => {
        //first swap which takes all the allowance
        const newNumberOfSwapsLimitPerUser = 2;
        const newBlocksPerLimit = 3;
        let values = [0, 0, 0];
        let targets = [stableSwapModule.address, stableSwapModule.address, stableSwapModule.address];
        let calldatas = [
          stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true]),
          stableSwapModule.interface.encodeFunctionData("setNumberOfSwapsLimitPerUser", [newNumberOfSwapsLimitPerUser]),
          stableSwapModule.interface.encodeFunctionData("setBlocksPerLimit", [newBlocksPerLimit]),
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        // await stableSwapModule.setNumberOfSwapsLimitPerUser(newNumberOfSwapsLimitPerUser);
        // await stableSwapModule.setBlocksPerLimit(newBlocksPerLimit);

        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT);

        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );

        await expect(
          stableSwapModule.swapTokenToStablecoin(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          )
        ).to.be.revertedWith("_updateAndCheckNumberOfSwapsInBlocksPerLimit/swap-limit-exceeded");
      });
    });
    context("check for block limit", async () => {
      it("Should be successful and not reach limit - setting 3 swaps per 3 blocks", async () => {
        //first swap which takes all the allowance
        const newNumberOfSwapsLimitPerUser = 3;
        const newBlocksPerLimit = 3;

        let values = [0, 0, 0];
        let targets = [stableSwapModule.address, stableSwapModule.address, stableSwapModule.address];
        let calldatas = [
          stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true]),
          stableSwapModule.interface.encodeFunctionData("setNumberOfSwapsLimitPerUser", [newNumberOfSwapsLimitPerUser]),
          stableSwapModule.interface.encodeFunctionData("setBlocksPerLimit", [newBlocksPerLimit]),
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        // await stableSwapModule.setNumberOfSwapsLimitPerUser(newNumberOfSwapsLimitPerUser);
        // await stableSwapModule.setBlocksPerLimit(newBlocksPerLimit);

        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT);

        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );

        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );

        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );
      });
    });
    context("check for block limit", async () => {
      it("Should revert for extra swap in the limit and then again be sucessful after enough block passes", async () => {
        //first swap which takes all the allowance
        const newNumberOfSwapsLimitPerUser = 3;
        const newBlocksPerLimit = 10;
        const blockNumbersToReachForNextSwap = 12;
        let values = [0, 0, 0];
        let targets = [stableSwapModule.address, stableSwapModule.address, stableSwapModule.address];
        let calldatas = [
          stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true]),
          stableSwapModule.interface.encodeFunctionData("setNumberOfSwapsLimitPerUser", [newNumberOfSwapsLimitPerUser]),
          stableSwapModule.interface.encodeFunctionData("setBlocksPerLimit", [newBlocksPerLimit]),
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        // await stableSwapModule.setNumberOfSwapsLimitPerUser(newNumberOfSwapsLimitPerUser);
        // await stableSwapModule.setBlocksPerLimit(newBlocksPerLimit);

        await stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT);
        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );
        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );
        //This should fail because its 4th swap within 500 block window
        await expect(
          stableSwapModule.swapTokenToStablecoin(
            DeployerAddress,
            ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
          )
        ).to.be.revertedWith("_updateAndCheckNumberOfSwapsInBlocksPerLimit/swap-limit-exceeded");
        for (let i = 0; i < blockNumbersToReachForNextSwap; i++) {
          await hre.network.provider.send("hardhat_mine", ["0x01"]);
        }

        await stableSwapModule.swapStablecoinToToken(
          DeployerAddress,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(DIVIDER_TO_FIT_SINGLE_SWAP_LIMIT))
        );
      });
    });
  });

  describe("#stableSwapEmergencyWithdraw", async () => {
    context("emergency withdraw", async () => {
      it("Should emergency withdraw when paused", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("emergencyWithdraw", [accounts[5].address])];
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

        await expect(governor.execute(targets, values, calldatas, descriptionHash)).to.be.reverted;
        // await expect(stableSwapModule.emergencyWithdraw(accounts[5].address)).to.be.reverted;

        values = [0, 0];
        targets = [stableSwapModule.address, stableSwapModule.address];
        calldatas = [
          stableSwapModule.interface.encodeFunctionData("pause"),
          stableSwapModule.interface.encodeFunctionData("emergencyWithdraw", [accounts[5].address]),
        ];
        proposalTx = await governor.propose(targets, values, calldatas, "Setup");
        proposalReceipt = await proposalTx.wait();
        proposalId = proposalReceipt.events[0].args.proposalId;

        // wait for the voting period to pass
        await mine(VOTING_DELAY + 1); // wait for the voting period to pass

        await governor.connect(provider.getSigner(DeployerAddress)).castVote(proposalId, VOTE_WAY);

        await mine(VOTING_PERIOD + 1);

        // Queue the TX
        descriptionHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Setup"));
        await governor.queue(targets, values, calldatas, descriptionHash);

        await time.increase(MIN_DELAY + 1);
        await mine(1);

        await governor.execute(targets, values, calldatas, descriptionHash);
        // await stableSwapModule.pause();
        // await stableSwapModule.emergencyWithdraw(accounts[5].address);
        const balanceOfStablecoin = await fathomStablecoin.balanceOf(accounts[5].address);
        const balanceOfToken = await USDT.balanceOf(accounts[5].address);
        expect(balanceOfStablecoin).to.be.equal(ethers.utils.parseEther("10000000"));
        expect(balanceOfToken).to.be.equal(WeiPerSixDecimals.mul(10000000));
      });
    });
  });

  describe("#StableswapMultipleSwapsMock", async () => {
    context("twoStablecoinToTokenSwapAtSameBlock- swap tokens in same block", async () => {
      it("should revert if we swap tokens in same block", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);

        await fathomStablecoin.approve(stableswapMultipleSwapsMock.address, ethers.constants.MaxUint256);
        await expect(
          stableswapMultipleSwapsMock.twoStablecoinToTokenSwapAtSameBlock(
            stableSwapModule.address,
            fathomStablecoin.address,
            ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(5000))
          )
        ).to.be.revertedWith("_updateAndCheckNumberOfSwapsInBlocksPerLimit/swap-limit-exceeded");
      });
    });

    context("twoTokenToStablecoinSwapAtSameBlock- swap tokens in same block", async () => {
      it("should revert if we swap tokens in same block", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);

        await USDT.approve(stableswapMultipleSwapsMock.address, ethers.constants.MaxUint256);
        await expect(
          stableswapMultipleSwapsMock.twoTokenToStablecoinSwapAtSameBlock(
            stableSwapModule.address,
            USDT.address,
            ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(5000))
          )
        ).to.be.revertedWith("_updateAndCheckNumberOfSwapsInBlocksPerLimit/swap-limit-exceeded");
      });
    });
    context("twoStablecoinToTokenSwapAtSameBlock- swap tokens in same block", async () => {
      it("Should be successful for two swaps in same block", async () => {
        const newNumberOfSwapsLimitPerUser = 3;
        const newBlocksPerLimit = 1;
        let values = [0, 0, 0];
        let targets = [stableSwapModule.address, stableSwapModule.address, stableSwapModule.address];
        let calldatas = [
          stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true]),
          stableSwapModule.interface.encodeFunctionData("setNumberOfSwapsLimitPerUser", [newNumberOfSwapsLimitPerUser]),
          stableSwapModule.interface.encodeFunctionData("setBlocksPerLimit", [newBlocksPerLimit]),
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        // await stableSwapModule.setNumberOfSwapsLimitPerUser(newNumberOfSwapsLimitPerUser);
        // await stableSwapModule.setBlocksPerLimit(newBlocksPerLimit);

        await fathomStablecoin.approve(stableswapMultipleSwapsMock.address, ethers.constants.MaxUint256);
        await stableswapMultipleSwapsMock.twoStablecoinToTokenSwapAtSameBlock(
          stableSwapModule.address,
          fathomStablecoin.address,
          ONE_PERCENT_OF_TOTAL_DEPOSIT.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT.div(4000))
        );
      });
    });

    context("twoTokenToStablecoinSwapAtSameBlock- swap tokens in same block", async () => {
      it("Should be successful for two swaps in same block", async () => {
        const newNumberOfSwapsLimitPerUser = 3;
        const newBlocksPerLimit = 1;
        let values = [0, 0, 0];
        let targets = [stableSwapModule.address, stableSwapModule.address, stableSwapModule.address];
        let calldatas = [
          stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true]),
          stableSwapModule.interface.encodeFunctionData("setNumberOfSwapsLimitPerUser", [newNumberOfSwapsLimitPerUser]),
          stableSwapModule.interface.encodeFunctionData("setBlocksPerLimit", [newBlocksPerLimit]),
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        // await stableSwapModule.setNumberOfSwapsLimitPerUser(newNumberOfSwapsLimitPerUser);
        // await stableSwapModule.setBlocksPerLimit(newBlocksPerLimit);

        await USDT.approve(stableswapMultipleSwapsMock.address, ethers.constants.MaxUint256);
        await stableswapMultipleSwapsMock.twoTokenToStablecoinSwapAtSameBlock(
          stableSwapModule.address,
          USDT.address,
          ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.sub(ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.div(4000))
        );
      });
    });
  });

  describe("#stableswapNotWhitelistedUserSwaps", async () => {
    context("not whitelisted-swapTokenToStablecoin", () => {
      it("should revert -  fail if the decentralized state is not activated and sender is not whitelisted", async () => {
        await expect(
          stableSwapModule.connect(provider.getSigner(accounts[2].address)).swapTokenToStablecoin(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT)
        ).to.be.revertedWith("user-not-whitelisted");
      });
    });
    context("not whitelisted-swapStablecoinToToken", () => {
      it("should revert -  fail if the decentralized state is not activated and sender is not whitelisted", async () => {
        await expect(
          stableSwapModule.connect(provider.getSigner(accounts[2].address)).swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT)
        ).to.be.revertedWith("user-not-whitelisted");
      });
    });
  });

  describe("#getIsUsersWhitelisted", async () => {
    context("is whitelisted should be true", () => {
      it("should return true", async () => {
        const isUserWhitelisted = await stableSwapModule.isUserWhitelisted(DeployerAddress);
        expect(isUserWhitelisted).to.be.equal(true);
      });
    });

    context("is whitelisted should be true", () => {
      it("should return false", async () => {
        const isUserWhitelisted = await stableSwapModule.isUserWhitelisted(accounts[2].address);
        expect(isUserWhitelisted).to.be.equal(false);
      });
    });
  });

  describe("#totalValueDeposited", async () => {
    context("update total value deposited after upgrade", async () => {
      it("totalValueDeposited: should be same before and after upgrade", async () => {
        const totalValueDepositedBeforeUpdate = await stableSwapModule.totalValueDeposited();
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("udpateTotalValueDeposited")];
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
        // await stableSwapModule.udpateTotalValueDeposited();
        const totalValueDepositedAfterUpdate = await stableSwapModule.totalValueDeposited();
        expect(totalValueDepositedAfterUpdate).to.be.equal(totalValueDepositedBeforeUpdate);
      });
    });
  });

  describe("#unitTests", async () => {
    context("exceed single swap limit", () => {
      it("should revert after setting decentralized state - single swap limit - swapStablecoinToToken", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        await expect(stableSwapModule.swapStablecoinToToken(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT.add(1))).to.be.revertedWith(
          "_checkSingleSwapLimit/single-swap-exceeds-limit"
        );
      });
    });

    context("exceed single swap limit", () => {
      it("should revert after setting decentralized state - single swap limit - swapTokenToStablecoin", async () => {
        let values = [0];
        let targets = [stableSwapModule.address];
        let calldatas = [stableSwapModule.interface.encodeFunctionData("setDecentralizedStatesStatus", [true])];
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
        // await stableSwapModule.setDecentralizedStatesStatus(true);
        await expect(stableSwapModule.swapTokenToStablecoin(DeployerAddress, ONE_PERCENT_OF_TOTAL_DEPOSIT_SIX_DECIMALS.add(1))).to.be.revertedWith(
          "_checkSingleSwapLimit/single-swap-exceeds-limit"
        );
      });
    });
  });
});
