// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../interfaces/ICrossCollateralManager.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/ICollateralPoolConfig.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../utils/CommonMath.sol";

/**
 * @title CrossCollateralManager
 * @notice Manages positions with multiple collateral types for improved capital efficiency
 * and risk diversification
 */
contract CrossCollateralManager is 
    CommonMath,
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable, 
    ICrossCollateralManager 
{
    uint256 public constant MIN_HEALTH_RATIO = 11e26; // 110% minimum
    uint256 public constant LIQUIDATION_THRESHOLD = 105e25; // 105% liquidation threshold
    uint256 public constant MAX_COLLATERAL_TYPES = 10; // Maximum collateral types per position
    uint256 public constant DEFAULT_RISK_WEIGHT = RAY; // 100% default weight
    uint256 public constant MIN_RISK_WEIGHT = 5e26; // 50% minimum weight
    uint256 public constant MAX_RISK_WEIGHT = 15e26; // 150% maximum weight

    IBookKeeper public bookKeeper;
    ICollateralPoolConfig public collateralPoolConfig;
    IAccessControlConfig public accessControlConfig;

    struct StoredCrossPosition {
        address owner;
        bytes32[] collateralPoolIds;
        mapping(bytes32 => uint256) collateralAmounts;
        uint256 totalDebtShare;
        uint256 weightedCollateralRatio;
        bool isActive;
        uint256 lastUpdateTime;
    }

    mapping(bytes32 => StoredCrossPosition) private crossPositions;
    mapping(address => bytes32[]) public userPositions;
    mapping(bytes32 => uint256) public riskWeights; // Pool ID => risk weight
    
    uint256 public liquidationThreshold;
    uint256 public nextPositionId;

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

    modifier onlyPositionOwner(bytes32 _positionId) {
        require(crossPositions[_positionId].owner == msg.sender, "CrossCollateralManager/not-owner");
        _;
    }

    modifier validPosition(bytes32 _positionId) {
        require(crossPositions[_positionId].isActive, "CrossCollateralManager/invalid-position");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _bookKeeper,
        uint256 _liquidationThreshold
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        
        require(_bookKeeper != address(0), "CrossCollateralManager/invalid-bookkeeper");
        require(_liquidationThreshold >= LIQUIDATION_THRESHOLD && _liquidationThreshold <= MIN_HEALTH_RATIO, 
                "CrossCollateralManager/invalid-liquidation-threshold");
        
        bookKeeper = IBookKeeper(_bookKeeper);
        collateralPoolConfig = ICollateralPoolConfig(bookKeeper.collateralPoolConfig());
        accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        
        liquidationThreshold = _liquidationThreshold;
        nextPositionId = 1;
    }

    function createCrossPosition(
        bytes32[] calldata _collateralPoolIds,
        uint256[] calldata _collateralAmounts,
        uint256 _debtAmount
    ) external override nonReentrant whenNotPaused returns (bytes32 positionId) {
        require(_collateralPoolIds.length == _collateralAmounts.length, "CrossCollateralManager/length-mismatch");
        require(_collateralPoolIds.length > 1 && _collateralPoolIds.length <= MAX_COLLATERAL_TYPES, 
                "CrossCollateralManager/invalid-collateral-count");
        require(_debtAmount > 0, "CrossCollateralManager/invalid-debt-amount");
        
        // Verify position safety before creation
        (uint256 healthRatio, bool isSafe) = calculateRequiredCollateral(_collateralPoolIds, _collateralAmounts, _debtAmount);
        require(isSafe && healthRatio >= MIN_HEALTH_RATIO, "CrossCollateralManager/unsafe-position");
        
        positionId = bytes32(nextPositionId++);
        StoredCrossPosition storage position = crossPositions[positionId];
        
        position.owner = msg.sender;
        position.collateralPoolIds = _collateralPoolIds;
        position.totalDebtShare = _debtAmount;
        position.isActive = true;
        position.lastUpdateTime = block.timestamp;
        
        // Store collateral amounts
        for (uint256 i = 0; i < _collateralPoolIds.length; i++) {
            require(_collateralAmounts[i] > 0, "CrossCollateralManager/invalid-collateral-amount");
            position.collateralAmounts[_collateralPoolIds[i]] = _collateralAmounts[i];
        }
        
        // Calculate weighted collateral ratio
        position.weightedCollateralRatio = _calculateWeightedCollateralRatio(positionId);
        
        // Add to user positions
        userPositions[msg.sender].push(positionId);
        
        emit LogCrossPositionCreated(positionId, msg.sender);
        return positionId;
    }

    function addCollateral(
        bytes32 _positionId,
        bytes32 _collateralPoolId,
        uint256 _amount
    ) external override nonReentrant whenNotPaused onlyPositionOwner(_positionId) validPosition(_positionId) returns (bool) {
        require(_amount > 0, "CrossCollateralManager/invalid-amount");
        
        StoredCrossPosition storage position = crossPositions[_positionId];
        
        // Check if this collateral type is already in the position
        bool poolExists = false;
        for (uint256 i = 0; i < position.collateralPoolIds.length; i++) {
            if (position.collateralPoolIds[i] == _collateralPoolId) {
                poolExists = true;
                break;
            }
        }
        
        if (!poolExists) {
            require(position.collateralPoolIds.length < MAX_COLLATERAL_TYPES, 
                    "CrossCollateralManager/max-collateral-types");
            position.collateralPoolIds.push(_collateralPoolId);
        }
        
        position.collateralAmounts[_collateralPoolId] += _amount;
        position.weightedCollateralRatio = _calculateWeightedCollateralRatio(_positionId);
        position.lastUpdateTime = block.timestamp;
        
        emit LogCollateralAdded(_positionId, _collateralPoolId, _amount);
        return true;
    }

    function removeCollateral(
        bytes32 _positionId,
        bytes32 _collateralPoolId,
        uint256 _amount
    ) external override nonReentrant whenNotPaused onlyPositionOwner(_positionId) validPosition(_positionId) returns (bool) {
        require(_amount > 0, "CrossCollateralManager/invalid-amount");
        
        StoredCrossPosition storage position = crossPositions[_positionId];
        require(position.collateralAmounts[_collateralPoolId] >= _amount, 
                "CrossCollateralManager/insufficient-collateral");
        
        // Check if position would remain safe after removal
        uint256 currentHealthRatio = calculateHealthRatio(_positionId);
        
        // Temporarily reduce collateral to check safety
        position.collateralAmounts[_collateralPoolId] -= _amount;
        uint256 newHealthRatio = calculateHealthRatio(_positionId);
        
        require(newHealthRatio >= MIN_HEALTH_RATIO, "CrossCollateralManager/would-be-unsafe");
        
        // If collateral amount becomes 0, remove from array
        if (position.collateralAmounts[_collateralPoolId] == 0) {
            _removeCollateralPoolId(position, _collateralPoolId);
        }
        
        position.weightedCollateralRatio = _calculateWeightedCollateralRatio(_positionId);
        position.lastUpdateTime = block.timestamp;
        
        emit LogCollateralRemoved(_positionId, _collateralPoolId, _amount);
        return true;
    }

    function adjustDebt(
        bytes32 _positionId,
        int256 _debtChange
    ) external override nonReentrant whenNotPaused onlyPositionOwner(_positionId) validPosition(_positionId) returns (bool) {
        require(_debtChange != 0, "CrossCollateralManager/zero-debt-change");
        
        StoredCrossPosition storage position = crossPositions[_positionId];
        
        if (_debtChange > 0) {
            // Increasing debt
            position.totalDebtShare += uint256(_debtChange);
        } else {
            // Decreasing debt
            uint256 debtReduction = uint256(-_debtChange);
            require(position.totalDebtShare >= debtReduction, "CrossCollateralManager/debt-underflow");
            position.totalDebtShare -= debtReduction;
        }
        
        // Verify position remains safe
        uint256 healthRatio = calculateHealthRatio(_positionId);
        require(healthRatio >= MIN_HEALTH_RATIO, "CrossCollateralManager/unsafe-after-adjustment");
        
        position.lastUpdateTime = block.timestamp;
        
        emit LogDebtAdjusted(_positionId, _debtChange, position.totalDebtShare);
        return true;
    }

    function liquidatePosition(
        bytes32 _positionId,
        uint256 _maxDebtToCover
    ) external override nonReentrant whenNotPaused validPosition(_positionId) returns (bool) {
        require(isPositionLiquidatable(_positionId), "CrossCollateralManager/position-not-liquidatable");
        require(_maxDebtToCover > 0, "CrossCollateralManager/invalid-debt-to-cover");
        
        StoredCrossPosition storage position = crossPositions[_positionId];
        
        uint256 debtToCover = _maxDebtToCover > position.totalDebtShare ? position.totalDebtShare : _maxDebtToCover;
        
        // Calculate total collateral value for proportional liquidation
        uint256 totalCollateralValue = _calculateTotalCollateralValue(_positionId);
        
        // Liquidate proportionally across all collateral types
        for (uint256 i = 0; i < position.collateralPoolIds.length; i++) {
            bytes32 poolId = position.collateralPoolIds[i];
            uint256 collateralAmount = position.collateralAmounts[poolId];
            if (collateralAmount > 0) {
                uint256 collateralToLiquidate = (collateralAmount * debtToCover) / position.totalDebtShare;
                position.collateralAmounts[poolId] -= collateralToLiquidate;
            }
        }
        
        position.totalDebtShare -= debtToCover;
        
        // If position is fully liquidated, deactivate it
        if (position.totalDebtShare == 0) {
            position.isActive = false;
        }
        
        position.weightedCollateralRatio = _calculateWeightedCollateralRatio(_positionId);
        position.lastUpdateTime = block.timestamp;
        
        emit LogPositionLiquidated(_positionId, totalCollateralValue, debtToCover);
        return true;
    }

    function getPositionSummary(bytes32 _positionId) external view override validPosition(_positionId) returns (PositionSummary memory) {
        StoredCrossPosition storage position = crossPositions[_positionId];
        
        CollateralInfo[] memory collaterals = new CollateralInfo[](position.collateralPoolIds.length);
        uint256 totalCollateralValue = 0;
        
        for (uint256 i = 0; i < position.collateralPoolIds.length; i++) {
            bytes32 poolId = position.collateralPoolIds[i];
            uint256 amount = position.collateralAmounts[poolId];
            uint256 value = _getCollateralValue(poolId, amount);
            
            collaterals[i] = CollateralInfo({
                poolId: poolId,
                amount: amount,
                value: value,
                weight: riskWeights[poolId] == 0 ? DEFAULT_RISK_WEIGHT : riskWeights[poolId],
                liquidationThreshold: liquidationThreshold
            });
            
            totalCollateralValue += value;
        }
        
        uint256 totalDebtValue = _getTotalDebtValue(_positionId);
        uint256 healthRatio = totalDebtValue > 0 ? (totalCollateralValue * RAY) / totalDebtValue : type(uint256).max;
        
        return PositionSummary({
            owner: position.owner,
            totalCollateralValue: totalCollateralValue,
            totalDebtValue: totalDebtValue,
            healthRatio: healthRatio,
            liquidationThreshold: liquidationThreshold,
            collaterals: collaterals,
            isActive: position.isActive
        });
    }

    function calculateHealthRatio(bytes32 _positionId) public view override validPosition(_positionId) returns (uint256) {
        uint256 totalCollateralValue = _calculateTotalCollateralValue(_positionId);
        uint256 totalDebtValue = _getTotalDebtValue(_positionId);
        
        if (totalDebtValue == 0) {
            return type(uint256).max;
        }
        
        return (totalCollateralValue * RAY) / totalDebtValue;
    }

    function getPositionOwner(bytes32 _positionId) external view override returns (address) {
        return crossPositions[_positionId].owner;
    }

    function isPositionLiquidatable(bytes32 _positionId) public view override validPosition(_positionId) returns (bool) {
        uint256 healthRatio = calculateHealthRatio(_positionId);
        return healthRatio < liquidationThreshold;
    }

    function calculateRequiredCollateral(
        bytes32[] calldata _collateralPoolIds,
        uint256[] calldata _collateralAmounts,
        uint256 _debtAmount
    ) public view override returns (uint256 healthRatio, bool isSafe) {
        require(_collateralPoolIds.length == _collateralAmounts.length, "CrossCollateralManager/length-mismatch");
        
        uint256 totalCollateralValue = 0;
        
        for (uint256 i = 0; i < _collateralPoolIds.length; i++) {
            uint256 collateralValue = _getCollateralValue(_collateralPoolIds[i], _collateralAmounts[i]);
            totalCollateralValue += collateralValue;
        }
        
        if (_debtAmount == 0) {
            return (type(uint256).max, true);
        }
        
        healthRatio = (totalCollateralValue * RAY) / _debtAmount;
        isSafe = healthRatio >= MIN_HEALTH_RATIO;
        
        return (healthRatio, isSafe);
    }

    function _calculateWeightedCollateralRatio(bytes32 _positionId) internal view returns (uint256) {
        StoredCrossPosition storage position = crossPositions[_positionId];
        uint256 weightedValue = 0;
        uint256 totalValue = 0;
        
        for (uint256 i = 0; i < position.collateralPoolIds.length; i++) {
            bytes32 poolId = position.collateralPoolIds[i];
            uint256 amount = position.collateralAmounts[poolId];
            uint256 value = _getCollateralValue(poolId, amount);
            uint256 weight = riskWeights[poolId] == 0 ? DEFAULT_RISK_WEIGHT : riskWeights[poolId];
            
            weightedValue += (value * weight) / RAY;
            totalValue += value;
        }
        
        return totalValue > 0 ? (weightedValue * RAY) / totalValue : 0;
    }

    function _calculateTotalCollateralValue(bytes32 _positionId) internal view returns (uint256) {
        StoredCrossPosition storage position = crossPositions[_positionId];
        uint256 totalValue = 0;
        
        for (uint256 i = 0; i < position.collateralPoolIds.length; i++) {
            bytes32 poolId = position.collateralPoolIds[i];
            uint256 amount = position.collateralAmounts[poolId];
            totalValue += _getCollateralValue(poolId, amount);
        }
        
        return totalValue;
    }

    function _getCollateralValue(bytes32 _poolId, uint256 _amount) internal view returns (uint256) {
        uint256 priceWithSafetyMargin = collateralPoolConfig.getPriceWithSafetyMargin(_poolId);
        return (_amount * priceWithSafetyMargin) / RAY;
    }

    function _getTotalDebtValue(bytes32 _positionId) internal view returns (uint256) {
        StoredCrossPosition storage position = crossPositions[_positionId];
        // Simplified - in practice would need to calculate across all pools
        // For now, assuming uniform debt accumulation rate
        return position.totalDebtShare;
    }

    function _removeCollateralPoolId(StoredCrossPosition storage _position, bytes32 _poolId) internal {
        for (uint256 i = 0; i < _position.collateralPoolIds.length; i++) {
            if (_position.collateralPoolIds[i] == _poolId) {
                _position.collateralPoolIds[i] = _position.collateralPoolIds[_position.collateralPoolIds.length - 1];
                _position.collateralPoolIds.pop();
                break;
            }
        }
    }

    function setRiskWeight(bytes32 _poolId, uint256 _weight) external override onlyOwner {
        require(_weight >= MIN_RISK_WEIGHT && _weight <= MAX_RISK_WEIGHT, "CrossCollateralManager/invalid-risk-weight");
        uint256 oldWeight = riskWeights[_poolId];
        riskWeights[_poolId] = _weight;
        emit LogRiskWeightUpdated(_poolId, oldWeight, _weight);
    }

    function setLiquidationThreshold(uint256 _threshold) external override onlyOwner {
        require(_threshold >= LIQUIDATION_THRESHOLD && _threshold <= MIN_HEALTH_RATIO, 
                "CrossCollateralManager/invalid-threshold");
        liquidationThreshold = _threshold;
    }

    function getUserPositions(address _user) external view override returns (bytes32[] memory) {
        return userPositions[_user];
    }

    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
    }
}
