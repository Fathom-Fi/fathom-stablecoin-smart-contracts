// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

interface ICrossCollateralManager {
    struct CrossCollateralPosition {
        address owner;
        bytes32[] collateralPoolIds;
        mapping(bytes32 => uint256) collateralAmounts;
        uint256 totalDebtShare;
        uint256 weightedCollateralRatio;
        bool isActive;
        uint256 lastUpdateTime;
    }

    struct CollateralInfo {
        bytes32 poolId;
        uint256 amount;
        uint256 value; // In USD terms
        uint256 weight; // Risk weight for this collateral
        uint256 liquidationThreshold;
    }

    struct PositionSummary {
        address owner;
        uint256 totalCollateralValue;
        uint256 totalDebtValue;
        uint256 healthRatio;
        uint256 liquidationThreshold;
        CollateralInfo[] collaterals;
        bool isActive;
    }

    event LogCrossPositionCreated(bytes32 indexed positionId, address indexed owner);
    event LogCollateralAdded(bytes32 indexed positionId, bytes32 indexed poolId, uint256 amount);
    event LogCollateralRemoved(bytes32 indexed positionId, bytes32 indexed poolId, uint256 amount);
    event LogDebtAdjusted(bytes32 indexed positionId, int256 debtChange, uint256 newTotalDebt);
    event LogPositionLiquidated(bytes32 indexed positionId, uint256 totalCollateral, uint256 totalDebt);
    event LogRiskWeightUpdated(bytes32 indexed poolId, uint256 oldWeight, uint256 newWeight);

    function createCrossPosition(
        bytes32[] calldata _collateralPoolIds,
        uint256[] calldata _collateralAmounts,
        uint256 _debtAmount
    ) external returns (bytes32 positionId);

    function addCollateral(
        bytes32 _positionId,
        bytes32 _collateralPoolId,
        uint256 _amount
    ) external returns (bool);

    function removeCollateral(
        bytes32 _positionId,
        bytes32 _collateralPoolId,
        uint256 _amount
    ) external returns (bool);

    function adjustDebt(
        bytes32 _positionId,
        int256 _debtChange
    ) external returns (bool);

    function liquidatePosition(
        bytes32 _positionId,
        uint256 _maxDebtToCover
    ) external returns (bool);

    function getPositionSummary(bytes32 _positionId) 
        external view returns (PositionSummary memory);

    function calculateHealthRatio(bytes32 _positionId) 
        external view returns (uint256);

    function getPositionOwner(bytes32 _positionId) 
        external view returns (address);

    function isPositionLiquidatable(bytes32 _positionId) 
        external view returns (bool);

    function calculateRequiredCollateral(
        bytes32[] calldata _collateralPoolIds,
        uint256[] calldata _collateralAmounts,
        uint256 _debtAmount
    ) external view returns (uint256 healthRatio, bool isSafe);

    function setRiskWeight(bytes32 _poolId, uint256 _weight) external;
    function setLiquidationThreshold(uint256 _threshold) external;
    function getUserPositions(address _user) external view returns (bytes32[] memory);
}
