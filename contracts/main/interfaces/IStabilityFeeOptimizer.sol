// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

interface IStabilityFeeOptimizer {
    struct OptimizationParams {
        uint256 targetPeg; // Target peg price [ray]
        uint256 pegTolerance; // Acceptable deviation from peg [ray]
        uint256 adjustmentFactor; // Rate adjustment sensitivity [ray]
        uint256 maxRateChange; // Maximum rate change per adjustment [ray]
        uint256 minStabilityFee; // Minimum allowed stability fee [ray]
        uint256 maxStabilityFee; // Maximum allowed stability fee [ray]
        uint256 updateFrequency; // Minimum time between adjustments [seconds]
    }

    struct PegMetrics {
        uint256 currentPrice; // Current stablecoin price [ray]
        uint256 priceDeviation; // Deviation from target peg [ray]
        uint256 supply; // Total stablecoin supply [wad]
        uint256 demandPressure; // Demand pressure indicator [ray]
        uint256 lastUpdateTime; // Last metrics update timestamp
    }

    event LogStabilityFeeAdjusted(
        bytes32 indexed collateralPoolId,
        uint256 oldRate,
        uint256 newRate,
        uint256 priceDeviation,
        string reason
    );
    
    event LogOptimizationParamsUpdated(
        bytes32 indexed collateralPoolId,
        OptimizationParams params
    );
    
    event LogPegMetricsUpdated(
        uint256 currentPrice,
        uint256 priceDeviation,
        uint256 supply,
        uint256 demandPressure
    );

    function optimizeStabilityFees() external returns (bool);
    function optimizeCollateralPool(bytes32 _collateralPoolId) external returns (bool);
    function updatePegMetrics() external returns (bool);
    
    function setOptimizationParams(
        bytes32 _collateralPoolId,
        OptimizationParams calldata _params
    ) external;
    
    function getOptimizationParams(bytes32 _collateralPoolId) 
        external view returns (OptimizationParams memory);
    
    function getPegMetrics() external view returns (PegMetrics memory);
    
    function calculateOptimalRate(bytes32 _collateralPoolId) 
        external view returns (uint256);
    
    function shouldAdjustRate(bytes32 _collateralPoolId) 
        external view returns (bool, string memory reason);
    
    function estimateRateAdjustment(bytes32 _collateralPoolId) 
        external view returns (uint256 suggestedRate, string memory reason);
        
    function setStablecoinPriceOracle(address _priceOracle) external;
    function setUpdateFrequency(uint256 _frequency) external;
    function enableAutomaticOptimization(bool _enabled) external;
}
