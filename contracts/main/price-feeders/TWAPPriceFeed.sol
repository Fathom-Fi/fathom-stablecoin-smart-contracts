// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../interfaces/ITWAPPriceFeed.sol";
import "../interfaces/IPriceFeed.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../utils/CommonMath.sol";

/**
 * @title TWAPPriceFeed
 * @notice Time-Weighted Average Price feed that provides manipulation-resistant pricing
 * by averaging prices over configurable time windows
 */
contract TWAPPriceFeed is 
    CommonMath, 
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable, 
    ITWAPPriceFeed 
{
    uint256 public constant MINIMUM_WINDOW = 5 minutes;
    uint256 public constant MAXIMUM_WINDOW = 24 hours;
    uint256 public constant MINIMUM_OBSERVATION_WINDOW = 1 minutes;
    uint256 public constant MAXIMUM_OBSERVATIONS = 24; // 24 hours with 1 hour intervals
    
    IPriceFeed public basePriceFeed;
    IAccessControlConfig public accessControlConfig;
    bytes32 public override poolId;
    
    uint256 public window; // TWAP calculation window
    uint256 public observationWindow; // Frequency of price observations
    uint256 public lastObservationTime;
    
    PriceObservation[] public observations;
    mapping(uint256 => uint256) public observationIndex; // timestamp -> index
    
    uint256 private _observationPointer;
    bool private _initialized;

    modifier onlyOwner() {
        require(accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender), "!ownerRole");
        _;
    }

    modifier onlyOwnerOrGov() {
        require(
            accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender) ||
                accessControlConfig.hasRole(accessControlConfig.GOV_ROLE(), msg.sender),
            "!(ownerRole or govRole)"
        );
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _basePriceFeed,
        address _accessControlConfig,
        bytes32 _poolId,
        uint256 _window,
        uint256 _observationWindow
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        
        require(_basePriceFeed != address(0), "TWAPPriceFeed/invalid-base-price-feed");
        require(_accessControlConfig != address(0), "TWAPPriceFeed/invalid-access-control");
        require(_window >= MINIMUM_WINDOW && _window <= MAXIMUM_WINDOW, "TWAPPriceFeed/invalid-window");
        require(_observationWindow >= MINIMUM_OBSERVATION_WINDOW, "TWAPPriceFeed/invalid-observation-window");
        require(_poolId != bytes32(0), "TWAPPriceFeed/invalid-pool-id");
        
        basePriceFeed = IPriceFeed(_basePriceFeed);
        accessControlConfig = IAccessControlConfig(_accessControlConfig);
        poolId = _poolId;
        window = _window;
        observationWindow = _observationWindow;
        
        // Initialize with first observation
        _initializeFirstObservation();
    }

    function _initializeFirstObservation() internal {
        (uint256 price, bool isValid) = basePriceFeed.peekPrice();
        require(isValid && price > 0, "TWAPPriceFeed/invalid-initial-price");
        
        observations.push(PriceObservation({
            timestamp: block.timestamp,
            priceCumulative: 0, // First observation has 0 cumulative
            price: price
        }));
        
        lastObservationTime = block.timestamp;
        _initialized = true;
    }

    function updatePrice() external override nonReentrant whenNotPaused returns (bool) {
        require(_initialized, "TWAPPriceFeed/not-initialized");
        
        if (!canUpdate()) {
            return false;
        }
        
        (uint256 currentPrice, bool isValid) = basePriceFeed.peekPrice();
        require(isValid && currentPrice > 0, "TWAPPriceFeed/invalid-current-price");
        
        uint256 timeElapsed = block.timestamp - lastObservationTime;
        PriceObservation memory lastObservation = observations[observations.length - 1];
        
        // Calculate new cumulative price
        uint256 newPriceCumulative = lastObservation.priceCumulative + (lastObservation.price * timeElapsed);
        
        // Add new observation
        PriceObservation memory newObservation = PriceObservation({
            timestamp: block.timestamp,
            priceCumulative: newPriceCumulative,
            price: currentPrice
        });
        
        if (observations.length >= MAXIMUM_OBSERVATIONS) {
            // Replace oldest observation (circular buffer)
            observations[_observationPointer] = newObservation;
            _observationPointer = (_observationPointer + 1) % MAXIMUM_OBSERVATIONS;
        } else {
            observations.push(newObservation);
        }
        
        observationIndex[block.timestamp] = observations.length - 1;
        lastObservationTime = block.timestamp;
        
        (uint256 twapPrice, ) = getTWAPPrice();
        emit LogPriceUpdate(block.timestamp, currentPrice, twapPrice);
        
        return true;
    }

    function getTWAPPrice() public view override returns (uint256, bool) {
        return getTWAPPriceFor(window);
    }

    function getTWAPPriceFor(uint256 _window) public view override returns (uint256, bool) {
        require(_initialized, "TWAPPriceFeed/not-initialized");
        require(_window >= MINIMUM_WINDOW, "TWAPPriceFeed/window-too-small");
        
        if (observations.length < 2) {
            // Not enough observations for TWAP, return latest price
            return (observations[0].price, isPriceOk());
        }
        
        uint256 targetTime = block.timestamp - _window;
        PriceObservation memory latestObservation = observations[observations.length - 1];
        
        // If target time is before first observation, use entire available history
        if (targetTime <= observations[0].timestamp) {
            targetTime = observations[0].timestamp;
        }
        
        PriceObservation memory targetObservation = _getObservationAt(targetTime);
        
        uint256 timeElapsed = latestObservation.timestamp - targetObservation.timestamp;
        if (timeElapsed == 0) {
            return (latestObservation.price, isPriceOk());
        }
        
        // Calculate time-weighted average
        uint256 priceCumulativeDiff = latestObservation.priceCumulative - targetObservation.priceCumulative;
        
        // Add current period contribution
        uint256 currentPeriodContribution = latestObservation.price * (block.timestamp - latestObservation.timestamp);
        priceCumulativeDiff += currentPeriodContribution;
        timeElapsed += (block.timestamp - latestObservation.timestamp);
        
        uint256 twapPrice = priceCumulativeDiff / timeElapsed;
        
        return (twapPrice, isPriceOk());
    }

    function _getObservationAt(uint256 _timestamp) internal view returns (PriceObservation memory) {
        // Find the observation closest to the target timestamp
        PriceObservation memory closestObservation = observations[0];
        
        for (uint256 i = 0; i < observations.length; i++) {
            if (observations[i].timestamp <= _timestamp) {
                closestObservation = observations[i];
            } else {
                break;
            }
        }
        
        return closestObservation;
    }

    function peekPrice() external override returns (uint256, bool) {
        // Update price if possible
        if (canUpdate()) {
            this.updatePrice();
        }
        
        return getTWAPPrice();
    }

    function readPrice() external view override returns (uint256) {
        (uint256 price, ) = getTWAPPrice();
        return price;
    }

    function isPriceOk() public view override returns (bool) {
        if (!_initialized || paused()) {
            return false;
        }
        
        // Check if base price feed is healthy
        if (!basePriceFeed.isPriceOk()) {
            return false;
        }
        
        // Check if we have recent observations
        if (observations.length == 0) {
            return false;
        }
        
        uint256 latestTimestamp = observations[observations.length - 1].timestamp;
        return (block.timestamp - latestTimestamp) <= (observationWindow * 3); // Allow 3x observation window
    }

    function isPriceFresh() external view override returns (bool) {
        if (!_initialized || observations.length == 0) {
            return false;
        }
        
        uint256 latestTimestamp = observations[observations.length - 1].timestamp;
        return (block.timestamp - latestTimestamp) <= observationWindow;
    }

    function canUpdate() public view override returns (bool) {
        return _initialized && 
               (block.timestamp - lastObservationTime) >= observationWindow &&
               basePriceFeed.isPriceOk();
    }

    function getLatestObservation() external view returns (PriceObservation memory) {
        require(observations.length > 0, "TWAPPriceFeed/no-observations");
        return observations[observations.length - 1];
    }

    function setWindow(uint256 _newWindow) external override onlyOwner {
        require(_newWindow >= MINIMUM_WINDOW && _newWindow <= MAXIMUM_WINDOW, "TWAPPriceFeed/invalid-window");
        uint256 oldWindow = window;
        window = _newWindow;
        emit LogWindowUpdate(oldWindow, _newWindow);
    }

    function setObservationWindow(uint256 _newObservationWindow) external override onlyOwner {
        require(_newObservationWindow >= MINIMUM_OBSERVATION_WINDOW, "TWAPPriceFeed/invalid-observation-window");
        uint256 oldWindow = observationWindow;
        observationWindow = _newObservationWindow;
        emit LogObservationWindowUpdate(oldWindow, _newObservationWindow);
    }

    function setBasePriceFeed(address _newBasePriceFeed) external onlyOwner {
        require(_newBasePriceFeed != address(0), "TWAPPriceFeed/invalid-price-feed");
        basePriceFeed = IPriceFeed(_newBasePriceFeed);
    }

    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
        // Try to update price on unpause
        if (canUpdate()) {
            try this.updatePrice() {} catch {}
        }
    }

    // View functions for debugging and monitoring
    function getObservationsCount() external view returns (uint256) {
        return observations.length;
    }

    function getObservation(uint256 _index) external view returns (PriceObservation memory) {
        require(_index < observations.length, "TWAPPriceFeed/invalid-index");
        return observations[_index];
    }

    function getWindowUtilization() external view returns (uint256) {
        if (!_initialized || observations.length < 2) {
            return 0;
        }
        
        uint256 oldestTimestamp = observations[0].timestamp;
        uint256 availableHistory = block.timestamp - oldestTimestamp;
        
        return availableHistory >= window ? 10000 : (availableHistory * 10000) / window; // Return in basis points
    }
}
