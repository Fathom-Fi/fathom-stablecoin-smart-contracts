const { ethers } = require("hardhat");
const { expect } = require("chai");
const { parseEther } = ethers.utils;

const { WeiPerRay, WeiPerRad } = require("../helper/unit");

const { getProxy } = require("../../common/proxies");

xdescribe("FlastMintModule", () => {
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

  beforeEach(async () => {
    await deployments.fixture(["DeployTestFixture"]);
    const { deployer } = await getNamedAccounts();
    DeployerAddress = deployer;

    const ProxyFactory = await deployments.get("FathomProxyFactory");
    const proxyFactory = await ethers.getContractAt("FathomProxyFactory", ProxyFactory.address);

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

  //Silenced due to SSM being soon sunsetted and deprecated
  xdescribe("#flashLoan", async () => {
    context("receiver doesn't have enough tokens to return the loan + fee", async () => {
      it("should revert", async () => {
        await fathomStablecoin.mint(DeployerAddress, parseEther("3000"));
        await bookKeeper.mintUnbackedStablecoin(stablecoinAdapter.address, stablecoinAdapter.address, WeiPerRad.mul(3500));
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await flashMintModule.addToWhitelist(DeployerAddress);
        await stableSwapModule.addToWhitelist(flashMintArbitrager.address);
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
        await fathomStablecoin.mint(DeployerAddress, parseEther("3500"));
        await bookKeeper.mintUnbackedStablecoin(stablecoinAdapter.address, stablecoinAdapter.address, WeiPerRad.mul(3500));
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await flashMintModule.addToWhitelist(DeployerAddress);
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
  //Silenced due to SSM being soon sunsetted and deprecated
  xdescribe("#bookKeeperFlashLoan", async () => {
    context("receiver doesn't have enough tokens to return the loan + fee", async () => {
      it("should revert", async () => {
        await fathomStablecoin.mint(DeployerAddress, parseEther("3500"));
        await bookKeeper.mintUnbackedStablecoin(stablecoinAdapter.address, stablecoinAdapter.address, WeiPerRad.mul(3500));
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await flashMintModule.addToWhitelist(DeployerAddress);
        await stableSwapModule.addToWhitelist(bookKeeperFlashMintArbitrager.address);
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
        await fathomStablecoin.mint(DeployerAddress, parseEther("3500"));
        await bookKeeper.mintUnbackedStablecoin(stablecoinAdapter.address, stablecoinAdapter.address, WeiPerRad.mul(3500));
        await fathomStablecoin.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await USDT.mint(DeployerAddress, parseEther("3500"));
        await USDT.approve(stableSwapModuleWrapper.address, parseEther("3000"));
        await stableSwapModuleWrapper.depositTokens(parseEther("3000"));

        await flashMintModule.addToWhitelist(DeployerAddress);
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
