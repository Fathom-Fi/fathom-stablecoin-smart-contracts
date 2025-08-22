// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../interfaces/IStabilityFeeOptimizer.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/ICollateralPoolConfig.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../interfaces/IPriceOracle.sol";
import "../interfaces/IStablecoin.sol";
import "../utils/CommonMath.sol";

/**
 * @title StabilityFeeOptimizer
 * @notice Automatically adjusts stability fees based on peg health and market conditions
 * to maintain stablecoin stability and optimal system parameters
 */
contract StabilityFeeOptimizer is 
    CommonMath,
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable, 
    IStabilityFeeOptimizer 
{
    uint256 public constant DEFAULT_TARGET_PEG = 1e27; // $1 in ray
    uint256 public constant DEFAULT_PEG_TOLERANCE = 5e24; // 0.5% in ray
    uint256 public constant DEFAULT_ADJUSTMENT_FACTOR = 2e27; // 2x sensitivity
    uint256 public constant DEFAULT_MAX_RATE_CHANGE = 5e24; // 0.5% max change per adjustment
    uint256 public constant MIN_STABILITY_FEE = 1e27; // 0% minimum (ray format)
    uint256 public constant MAX_STABILITY_FEE = 1000000012857214317438491659; // ~50% yearly maximum
    uint256 public constant MIN_UPDATE_FREQUENCY = 1 hours;
    uint256 public constant MAX_UPDATE_FREQUENCY = 7 days;
    
    IBookKeeper public bookKeeper;
    ICollateralPoolConfig public collateralPoolConfig;
    IAccessControlConfig public accessControlConfig;
    IStablecoin public stablecoin;
    IPriceOracle public stablecoinPriceOracle;
    
    mapping(bytes32 => OptimizationParams) public optimizationParams;
    mapping(bytes32 => uint256) public lastAdjustmentTime;
    
    PegMetrics public pegMetrics;
    bool public automaticOptimizationEnabled;
    uint256 public globalUpdateFrequency;

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

    modifier onlyAuthorized() {
        require(
            accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender) ||
                accessControlConfig.hasRole(accessControlConfig.GOV_ROLE(), msg.sender) ||
                automaticOptimizationEnabled,
            "!authorized"
        );
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _bookKeeper,
        address _stablecoin,
        address _stablecoinPriceOracle,
        uint256 _globalUpdateFrequency
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        
        require(_bookKeeper != address(0), "StabilityFeeOptimizer/invalid-bookkeeper");
        require(_stablecoin != address(0), "StabilityFeeOptimizer/invalid-stablecoin");
        require(_stablecoinPriceOracle != address(0), "StabilityFeeOptimizer/invalid-price-oracle");
        require(_globalUpdateFrequency >= MIN_UPDATE_FREQUENCY && _globalUpdateFrequency <= MAX_UPDATE_FREQUENCY, 
                "StabilityFeeOptimizer/invalid-frequency");
        
        bookKeeper = IBookKeeper(_bookKeeper);
        collateralPoolConfig = ICollateralPoolConfig(bookKeeper.collateralPoolConfig());
        accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        stablecoin = IStablecoin(_stablecoin);
        stablecoinPriceOracle = IPriceOracle(_stablecoinPriceOracle);
        globalUpdateFrequency = _globalUpdateFrequency;
        
        // Initialize peg metrics
        _updatePegMetrics();
    }

    function optimizeStabilityFees() external override nonReentrant onlyAuthorized whenNotPaused returns (bool) {
        // Update peg metrics first
        updatePegMetrics();
        
        // This would need to iterate through all active collateral pools
        // For now, we'll demonstrate with a placeholder
        // In production, this would get all pool IDs from the config contract
        
        bytes32[] memory poolIds = _getActiveCollateralPools();
        bool anyAdjusted = false;
        
        for (uint256 i = 0; i < poolIds.length; i++) {
            if (optimizeCollateralPool(poolIds[i])) {
                anyAdjusted = true;
            }
        }
        
        return anyAdjusted;
    }

    function optimizeCollateralPool(bytes32 _collateralPoolId) public override nonReentrant onlyAuthorized whenNotPaused returns (bool) {
        OptimizationParams memory params = optimizationParams[_collateralPoolId];
        
        // Use default params if not set
        if (params.targetPeg == 0) {
            params = _getDefaultParams();
        }
        
        // Check if adjustment is needed
        (bool shouldAdjust, string memory reason) = shouldAdjustRate(_collateralPoolId);
        if (!shouldAdjust) {
            return false;
        }
        
        // Check update frequency
        if (block.timestamp < lastAdjustmentTime[_collateralPoolId] + params.updateFrequency) {
            return false;
        }
        
        uint256 currentRate = collateralPoolConfig.getStabilityFeeRate(_collateralPoolId);
        uint256 optimalRate = calculateOptimalRate(_collateralPoolId);
        
        // Apply maximum change limit
        uint256 maxChange = (currentRate * params.maxRateChange) / RAY;
        uint256 newRate;
        
        if (optimalRate > currentRate) {
            newRate = currentRate + maxChange > optimalRate ? optimalRate : currentRate + maxChange;
        } else {
            newRate = currentRate - maxChange < optimalRate ? optimalRate : currentRate - maxChange;
        }
        
        // Ensure rate is within bounds
        newRate = newRate < params.minStabilityFee ? params.minStabilityFee : newRate;
        newRate = newRate > params.maxStabilityFee ? params.maxStabilityFee : newRate;
        
        // Only update if change is significant (> 0.01%)
        if (abs(newRate, currentRate) > 1e23) {
            // Update the stability fee
            // Note: This would need to be called by an authorized role
            // collateralPoolConfig.setStabilityFeeRate(_collateralPoolId, newRate);
            
            lastAdjustmentTime[_collateralPoolId] = block.timestamp;
            
            emit LogStabilityFeeAdjusted(_collateralPoolId, currentRate, newRate, pegMetrics.priceDeviation, reason);
            return true;
        }
        
        return false;
    }

    function updatePegMetrics() public override nonReentrant whenNotPaused returns (bool) {
        return _updatePegMetrics();
    }

    function _updatePegMetrics() internal returns (bool) {
        uint256 currentPrice = stablecoinPriceOracle.stableCoinReferencePrice();
        uint256 totalSupply = stablecoin.totalSupply();
        
        uint256 priceDeviation = abs(currentPrice, DEFAULT_TARGET_PEG);
        uint256 demandPressure = _calculateDemandPressure(currentPrice, totalSupply);
        
        pegMetrics = PegMetrics({
            currentPrice: currentPrice,
            priceDeviation: priceDeviation,
            supply: totalSupply,
            demandPressure: demandPressure,
            lastUpdateTime: block.timestamp
        });
        
        emit LogPegMetricsUpdated(currentPrice, priceDeviation, totalSupply, demandPressure);
        return true;
    }

    function _calculateDemandPressure(uint256 _currentPrice, uint256 _totalSupply) internal view returns (uint256) {
        // Simplified demand pressure calculation
        // In practice, this would consider more factors like:
        // - Trading volume
        // - Liquidity pool ratios
        // - Mint/burn rates
        // - Market sentiment indicators
        
        uint256 priceRatio = (_currentPrice * RAY) / DEFAULT_TARGET_PEG;
        uint256 supplyFactor = _totalSupply > 0 ? RAY : 0;
        
        // Higher price = higher demand pressure
        return (priceRatio * supplyFactor) / RAY;
    }

    function calculateOptimalRate(bytes32 _collateralPoolId) public view override returns (uint256) {
        OptimizationParams memory params = optimizationParams[_collateralPoolId];
        if (params.targetPeg == 0) {
            params = _getDefaultParams();
        }
        
        uint256 currentRate = collateralPoolConfig.getStabilityFeeRate(_collateralPoolId);
        
        // If price is above peg, decrease rates to encourage borrowing
        // If price is below peg, increase rates to discourage borrowing
        if (pegMetrics.currentPrice > params.targetPeg + params.pegTolerance) {
            // Price too high - decrease rates
            uint256 adjustment = (pegMetrics.priceDeviation * params.adjustmentFactor) / RAY;
            return currentRate > adjustment ? currentRate - adjustment : params.minStabilityFee;
        } else if (pegMetrics.currentPrice < params.targetPeg - params.pegTolerance) {
            // Price too low - increase rates
            uint256 adjustment = (pegMetrics.priceDeviation * params.adjustmentFactor) / RAY;
            uint256 newRate = currentRate + adjustment;
            return newRate > params.maxStabilityFee ? params.maxStabilityFee : newRate;
        }
        
        // Price within tolerance - maintain current rate
        return currentRate;
    }

    function shouldAdjustRate(bytes32 _collateralPoolId) public view override returns (bool, string memory) {
        OptimizationParams memory params = optimizationParams[_collateralPoolId];
        if (params.targetPeg == 0) {
            params = _getDefaultParams();
        }
        
        // Check if peg metrics are fresh
        if (block.timestamp - pegMetrics.lastUpdateTime > globalUpdateFrequency) {
            return (false, "Stale peg metrics");
        }
        
        // Check if price is outside tolerance
        if (pegMetrics.priceDeviation > params.pegTolerance) {
            if (pegMetrics.currentPrice > params.targetPeg) {
                return (true, "Price above peg - decrease rates");
            } else {
                return (true, "Price below peg - increase rates");
            }
        }
        
        // Check demand pressure
        if (pegMetrics.demandPressure > 15e26) { // 1.5x normal
            return (true, "High demand pressure");
        } else if (pegMetrics.demandPressure < 5e26) { // 0.5x normal
            return (true, "Low demand pressure");
        }
        
        return (false, "No adjustment needed");
    }

    function estimateRateAdjustment(bytes32 _collateralPoolId) external view override returns (uint256, string memory) {
        (bool shouldAdjust, string memory reason) = shouldAdjustRate(_collateralPoolId);
        if (!shouldAdjust) {
            uint256 currentRate = collateralPoolConfig.getStabilityFeeRate(_collateralPoolId);
            return (currentRate, reason);
        }
        
        uint256 optimalRate = calculateOptimalRate(_collateralPoolId);
        return (optimalRate, reason);
    }

    function setOptimizationParams(
        bytes32 _collateralPoolId,
        OptimizationParams calldata _params
    ) external override onlyOwner {
        require(_params.targetPeg > 0, "StabilityFeeOptimizer/invalid-target-peg");
        require(_params.pegTolerance > 0, "StabilityFeeOptimizer/invalid-tolerance");
        require(_params.adjustmentFactor > 0, "StabilityFeeOptimizer/invalid-adjustment-factor");
        require(_params.maxRateChange > 0 && _params.maxRateChange <= RAY, "StabilityFeeOptimizer/invalid-max-change");
        require(_params.minStabilityFee >= MIN_STABILITY_FEE, "StabilityFeeOptimizer/invalid-min-fee");
        require(_params.maxStabilityFee <= MAX_STABILITY_FEE && _params.maxStabilityFee > _params.minStabilityFee, 
                "StabilityFeeOptimizer/invalid-max-fee");
        require(_params.updateFrequency >= MIN_UPDATE_FREQUENCY && _params.updateFrequency <= MAX_UPDATE_FREQUENCY,
                "StabilityFeeOptimizer/invalid-update-frequency");
        
        optimizationParams[_collateralPoolId] = _params;
        emit LogOptimizationParamsUpdated(_collateralPoolId, _params);
    }

    function getOptimizationParams(bytes32 _collateralPoolId) external view override returns (OptimizationParams memory) {
        OptimizationParams memory params = optimizationParams[_collateralPoolId];
        return params.targetPeg == 0 ? _getDefaultParams() : params;
    }

    function getPegMetrics() external view override returns (PegMetrics memory) {
        return pegMetrics;
    }

    function _getDefaultParams() internal pure returns (OptimizationParams memory) {
        return OptimizationParams({
            targetPeg: DEFAULT_TARGET_PEG,
            pegTolerance: DEFAULT_PEG_TOLERANCE,
            adjustmentFactor: DEFAULT_ADJUSTMENT_FACTOR,
            maxRateChange: DEFAULT_MAX_RATE_CHANGE,
            minStabilityFee: MIN_STABILITY_FEE,
            maxStabilityFee: MAX_STABILITY_FEE,
            updateFrequency: MIN_UPDATE_FREQUENCY
        });
    }

    function _getActiveCollateralPools() internal view returns (bytes32[] memory) {
        // Placeholder - in production this would query the collateral pool config
        // for all active pool IDs
        bytes32[] memory pools = new bytes32[](0);
        return pools;
    }

    function setStablecoinPriceOracle(address _priceOracle) external override onlyOwner {
        require(_priceOracle != address(0), "StabilityFeeOptimizer/invalid-oracle");
        stablecoinPriceOracle = IPriceOracle(_priceOracle);
    }

    function setUpdateFrequency(uint256 _frequency) external override onlyOwner {
        require(_frequency >= MIN_UPDATE_FREQUENCY && _frequency <= MAX_UPDATE_FREQUENCY, 
                "StabilityFeeOptimizer/invalid-frequency");
        globalUpdateFrequency = _frequency;
    }

    function enableAutomaticOptimization(bool _enabled) external override onlyOwner {
        automaticOptimizationEnabled = _enabled;
    }

    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    // Manual rate adjustment for emergency situations
    function emergencyRateAdjustment(
        bytes32 _collateralPoolId,
        uint256 _newRate,
        string calldata _reason
    ) external onlyOwner {
        require(_newRate >= MIN_STABILITY_FEE && _newRate <= MAX_STABILITY_FEE, 
                "StabilityFeeOptimizer/invalid-emergency-rate");
        
        uint256 currentRate = collateralPoolConfig.getStabilityFeeRate(_collateralPoolId);
        
        // This would need proper integration with CollateralPoolConfig
        // collateralPoolConfig.setStabilityFeeRate(_collateralPoolId, _newRate);
        
        lastAdjustmentTime[_collateralPoolId] = block.timestamp;
        
        emit LogStabilityFeeAdjusted(_collateralPoolId, currentRate, _newRate, 0, _reason);
    }
}
