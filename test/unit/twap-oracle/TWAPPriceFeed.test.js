const chai = require("chai");
const { ethers } = require("hardhat");
const { solidity } = require("ethereum-waffle");

chai.use(solidity);
const { expect } = chai;

const { DeployerAddress, AliceAddress, BobAddress } = require("../../helper/address");
const { formatBytes32String } = ethers.utils;

describe("TWAPPriceFeed", () => {
  let deployer, alice, bob;
  let twapPriceFeed;
  let mockBasePriceFeed;
  let mockAccessControlConfig;
  let poolId;

  const WINDOW_SIZE = 3600; // 1 hour
  const OBSERVATION_WINDOW = 300; // 5 minutes

  beforeEach(async () => {
    [deployer, alice, bob] = await ethers.getSigners();

    // Deploy mocks
    const MockPriceFeed = await ethers.getContractFactory("MockSimplePriceFeed");
    mockBasePriceFeed = await MockPriceFeed.deploy();
    await mockBasePriceFeed.deployed();

    const MockAccessControl = await ethers.getContractFactory("MockAdminControls");
    mockAccessControlConfig = await MockAccessControl.deploy();
    await mockAccessControlConfig.deployed();

    // Set up pool ID
    poolId = formatBytes32String("ETH-A");
    await mockBasePriceFeed.setPoolId(poolId);
    await mockBasePriceFeed.setPrice(ethers.utils.parseEther("2000")); // $2000

    // Deploy TWAP Price Feed
    const TWAPPriceFeed = await ethers.getContractFactory("TWAPPriceFeed");
    twapPriceFeed = await TWAPPriceFeed.deploy();
    await twapPriceFeed.deployed();

    // Initialize
    await twapPriceFeed.initialize(
      mockBasePriceFeed.address,
      mockAccessControlConfig.address,
      poolId,
      WINDOW_SIZE,
      OBSERVATION_WINDOW
    );
  });

  describe("#initialize", () => {
    it("should initialize with correct parameters", async () => {
      expect(await twapPriceFeed.basePriceFeed()).to.equal(mockBasePriceFeed.address);
      expect(await twapPriceFeed.accessControlConfig()).to.equal(mockAccessControlConfig.address);
      expect(await twapPriceFeed.poolId()).to.equal(poolId);
      expect(await twapPriceFeed.window()).to.equal(WINDOW_SIZE);
      expect(await twapPriceFeed.observationWindow()).to.equal(OBSERVATION_WINDOW);
    });

    it("should create initial observation", async () => {
      const observation = await twapPriceFeed.getLatestObservation();
      expect(observation.price).to.equal(ethers.utils.parseEther("2000"));
      expect(observation.priceCumulative).to.equal(0);
    });

    it("should revert on invalid parameters", async () => {
      const TWAPPriceFeed = await ethers.getContractFactory("TWAPPriceFeed");
      const newTwap = await TWAPPriceFeed.deploy();
      
      await expect(
        newTwap.initialize(
          ethers.constants.AddressZero,
          mockAccessControlConfig.address,
          poolId,
          WINDOW_SIZE,
          OBSERVATION_WINDOW
        )
      ).to.be.revertedWith("TWAPPriceFeed/invalid-base-price-feed");
    });
  });

  describe("#updatePrice", () => {
    it("should update price when observation window has passed", async () => {
      // Fast forward time
      await ethers.provider.send("evm_increaseTime", [OBSERVATION_WINDOW]);
      await ethers.provider.send("evm_mine");

      // Change base price
      await mockBasePriceFeed.setPrice(ethers.utils.parseEther("2100"));

      // Update price
      await expect(twapPriceFeed.updatePrice())
        .to.emit(twapPriceFeed, "LogPriceUpdate");

      const observation = await twapPriceFeed.getLatestObservation();
      expect(observation.price).to.equal(ethers.utils.parseEther("2100"));
    });

    it("should not update if observation window hasn't passed", async () => {
      // Try to update immediately
      const result = await twapPriceFeed.updatePrice();
      expect(result).to.be.false;
    });

    it("should calculate cumulative price correctly", async () => {
      // Get initial observation
      const initialObservation = await twapPriceFeed.getLatestObservation();
      const initialTime = initialObservation.timestamp;

      // Fast forward and update
      await ethers.provider.send("evm_increaseTime", [OBSERVATION_WINDOW]);
      await ethers.provider.send("evm_mine");

      await mockBasePriceFeed.setPrice(ethers.utils.parseEther("2100"));
      await twapPriceFeed.updatePrice();

      const newObservation = await twapPriceFeed.getLatestObservation();
      const expectedCumulative = ethers.utils.parseEther("2000").mul(OBSERVATION_WINDOW);
      
      expect(newObservation.priceCumulative).to.equal(expectedCumulative);
    });
  });

  describe("#getTWAPPrice", () => {
    it("should return latest price for insufficient history", async () => {
      const [price, isValid] = await twapPriceFeed.getTWAPPrice();
      expect(price).to.equal(ethers.utils.parseEther("2000"));
      expect(isValid).to.be.true;
    });

    it("should calculate TWAP correctly with sufficient history", async () => {
      // Create multiple observations
      for (let i = 0; i < 5; i++) {
        await ethers.provider.send("evm_increaseTime", [OBSERVATION_WINDOW]);
        await ethers.provider.send("evm_mine");
        
        const newPrice = ethers.utils.parseEther((2000 + i * 100).toString());
        await mockBasePriceFeed.setPrice(newPrice);
        await twapPriceFeed.updatePrice();
      }

      const [twapPrice, isValid] = await twapPriceFeed.getTWAPPrice();
      expect(isValid).to.be.true;
      // TWAP should be between initial and final prices
      expect(twapPrice).to.be.gt(ethers.utils.parseEther("2000"));
      expect(twapPrice).to.be.lt(ethers.utils.parseEther("2400"));
    });
  });

  describe("#peekPrice", () => {
    it("should update and return TWAP price", async () => {
      await ethers.provider.send("evm_increaseTime", [OBSERVATION_WINDOW]);
      await ethers.provider.send("evm_mine");

      await mockBasePriceFeed.setPrice(ethers.utils.parseEther("2050"));

      const [price, isValid] = await twapPriceFeed.peekPrice();
      expect(isValid).to.be.true;
      expect(price).to.be.gt(0);
    });
  });

  describe("#isPriceOk", () => {
    it("should return true when initialized and base feed is healthy", async () => {
      expect(await twapPriceFeed.isPriceOk()).to.be.true;
    });

    it("should return false when paused", async () => {
      await twapPriceFeed.pause();
      expect(await twapPriceFeed.isPriceOk()).to.be.false;
    });

    it("should return false when base price feed is unhealthy", async () => {
      await mockBasePriceFeed.setIsPriceOk(false);
      expect(await twapPriceFeed.isPriceOk()).to.be.false;
    });
  });

  describe("#setWindow", () => {
    it("should allow owner to update window", async () => {
      const newWindow = 7200; // 2 hours
      
      await expect(twapPriceFeed.setWindow(newWindow))
        .to.emit(twapPriceFeed, "LogWindowUpdate")
        .withArgs(WINDOW_SIZE, newWindow);

      expect(await twapPriceFeed.window()).to.equal(newWindow);
    });

    it("should revert on invalid window", async () => {
      await expect(
        twapPriceFeed.setWindow(60) // Too small
      ).to.be.revertedWith("TWAPPriceFeed/invalid-window");
    });

    it("should revert when called by non-owner", async () => {
      await expect(
        twapPriceFeed.connect(alice).setWindow(7200)
      ).to.be.revertedWith("!ownerRole");
    });
  });

  describe("#setObservationWindow", () => {
    it("should allow owner to update observation window", async () => {
      const newObservationWindow = 600; // 10 minutes
      
      await expect(twapPriceFeed.setObservationWindow(newObservationWindow))
        .to.emit(twapPriceFeed, "LogObservationWindowUpdate")
        .withArgs(OBSERVATION_WINDOW, newObservationWindow);

      expect(await twapPriceFeed.observationWindow()).to.equal(newObservationWindow);
    });
  });

  describe("#getWindowUtilization", () => {
    it("should return 0 for insufficient history", async () => {
      const utilization = await twapPriceFeed.getWindowUtilization();
      expect(utilization).to.equal(0);
    });

    it("should return correct utilization with history", async () => {
      // Create some history
      await ethers.provider.send("evm_increaseTime", [WINDOW_SIZE / 2]);
      await ethers.provider.send("evm_mine");

      await mockBasePriceFeed.setPrice(ethers.utils.parseEther("2100"));
      await twapPriceFeed.updatePrice();

      const utilization = await twapPriceFeed.getWindowUtilization();
      expect(utilization).to.be.gt(0);
      expect(utilization).to.be.lte(10000); // Should be <= 100% (10000 basis points)
    });
  });

  describe("Access Control", () => {
    it("should allow only authorized users to update configuration", async () => {
      // Try as unauthorized user
      await expect(
        twapPriceFeed.connect(alice).setWindow(7200)
      ).to.be.revertedWith("!ownerRole");

      await expect(
        twapPriceFeed.connect(alice).pause()
      ).to.be.revertedWith("!(ownerRole or govRole)");
    });
  });

  describe("Edge Cases", () => {
    it("should handle zero price correctly", async () => {
      await mockBasePriceFeed.setPrice(0);
      
      await ethers.provider.send("evm_increaseTime", [OBSERVATION_WINDOW]);
      await ethers.provider.send("evm_mine");

      await expect(twapPriceFeed.updatePrice()).to.be.revertedWith("TWAPPriceFeed/invalid-current-price");
    });

    it("should handle maximum observations correctly", async () => {
      // Create maximum number of observations
      for (let i = 0; i < 25; i++) { // More than MAXIMUM_OBSERVATIONS
        await ethers.provider.send("evm_increaseTime", [OBSERVATION_WINDOW]);
        await ethers.provider.send("evm_mine");
        
        await mockBasePriceFeed.setPrice(ethers.utils.parseEther((2000 + i).toString()));
        await twapPriceFeed.updatePrice();
      }

      // Should still work correctly with circular buffer
      const observationsCount = await twapPriceFeed.getObservationsCount();
      expect(observationsCount).to.be.lte(24); // MAXIMUM_OBSERVATIONS
    });
  });
});
