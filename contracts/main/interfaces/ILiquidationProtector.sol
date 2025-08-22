// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

interface ILiquidationProtector {
    struct ProtectionRequest {
        bytes32 collateralPoolId;
        address positionAddress;
        uint256 requestTimestamp;
        uint256 originalDebt;
        uint256 originalCollateral;
        uint256 targetHealthRatio;
        bool isActive;
    }

    event LogProtectionRequested(
        bytes32 indexed collateralPoolId,
        address indexed positionAddress,
        uint256 gracePeriodEnd,
        uint256 targetHealthRatio
    );
    
    event LogProtectionExecuted(
        bytes32 indexed collateralPoolId,
        address indexed positionAddress,
        uint256 collateralAdded,
        uint256 debtReduced,
        bool success
    );
    
    event LogProtectionExpired(
        bytes32 indexed collateralPoolId,
        address indexed positionAddress
    );
    
    event LogGracePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event LogMaxProtectionFeeUpdated(uint256 oldFee, uint256 newFee);

    function requestProtection(
        bytes32 _collateralPoolId,
        address _positionAddress,
        uint256 _targetHealthRatio
    ) external payable returns (bool);

    function executeProtection(
        bytes32 _collateralPoolId,
        address _positionAddress,
        uint256 _collateralToAdd,
        uint256 _debtToReduce
    ) external returns (bool);

    function cancelProtection(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external returns (bool);

    function isPositionProtected(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external view returns (bool);

    function getProtectionInfo(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external view returns (ProtectionRequest memory);

    function canExecuteLiquidation(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external view returns (bool);

    function calculateProtectionFee(
        bytes32 _collateralPoolId,
        uint256 _positionDebt
    ) external view returns (uint256);

    function setGracePeriod(uint256 _newGracePeriod) external;
    function setMaxProtectionFee(uint256 _newMaxFee) external;
}
