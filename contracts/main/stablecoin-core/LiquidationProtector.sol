// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../interfaces/ILiquidationProtector.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/ICollateralPoolConfig.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../utils/CommonMath.sol";

/**
 * @title LiquidationProtector
 * @notice Allows position owners to protect their positions from liquidation
 * by providing a grace period to add collateral or reduce debt
 */
contract LiquidationProtector is 
    CommonMath,
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable, 
    ILiquidationProtector 
{
    uint256 public constant MIN_GRACE_PERIOD = 30 minutes;
    uint256 public constant MAX_GRACE_PERIOD = 24 hours;
    uint256 public constant MIN_HEALTH_RATIO = 1.1e27; // 110% in ray
    uint256 public constant MAX_PROTECTION_FEE = 1e17; // 10% in wad
    uint256 public constant FEE_PRECISION = 1e18;

    IBookKeeper public bookKeeper;
    IAccessControlConfig public accessControlConfig;
    
    uint256 public gracePeriod; // Time window for protection
    uint256 public maxProtectionFee; // Maximum fee percentage
    address public feeRecipient; // Address to receive protection fees
    
    mapping(bytes32 => mapping(address => ProtectionRequest)) public protectionRequests;
    mapping(address => uint256) public totalFeesCollected;

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

    modifier onlyLiquidationEngine() {
        require(accessControlConfig.hasRole(accessControlConfig.LIQUIDATION_ENGINE_ROLE(), msg.sender), "!liquidationEngineRole");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _bookKeeper,
        address _accessControlConfig,
        address _feeRecipient,
        uint256 _gracePeriod,
        uint256 _maxProtectionFee
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        
        require(_bookKeeper != address(0), "LiquidationProtector/invalid-bookkeeper");
        require(_accessControlConfig != address(0), "LiquidationProtector/invalid-access-control");
        require(_feeRecipient != address(0), "LiquidationProtector/invalid-fee-recipient");
        require(_gracePeriod >= MIN_GRACE_PERIOD && _gracePeriod <= MAX_GRACE_PERIOD, "LiquidationProtector/invalid-grace-period");
        require(_maxProtectionFee <= MAX_PROTECTION_FEE, "LiquidationProtector/invalid-max-fee");
        
        bookKeeper = IBookKeeper(_bookKeeper);
        accessControlConfig = IAccessControlConfig(_accessControlConfig);
        feeRecipient = _feeRecipient;
        gracePeriod = _gracePeriod;
        maxProtectionFee = _maxProtectionFee;
    }

    function requestProtection(
        bytes32 _collateralPoolId,
        address _positionAddress,
        uint256 _targetHealthRatio
    ) external payable override nonReentrant whenNotPaused returns (bool) {
        require(_targetHealthRatio >= MIN_HEALTH_RATIO, "LiquidationProtector/insufficient-health-ratio");
        require(!isPositionProtected(_collateralPoolId, _positionAddress), "LiquidationProtector/already-protected");
        
        // Verify position exists and is underwater
        (uint256 lockedCollateral, uint256 debtShare) = bookKeeper.positions(_collateralPoolId, _positionAddress);
        require(lockedCollateral > 0 && debtShare > 0, "LiquidationProtector/invalid-position");
        
        // Check if position is actually at risk
        ICollateralPoolConfig.CollateralPoolInfo memory poolInfo = 
            ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getCollateralPoolInfo(_collateralPoolId);
        
        uint256 positionDebtValue = debtShare * poolInfo.debtAccumulatedRate;
        uint256 collateralValue = lockedCollateral * poolInfo.priceWithSafetyMargin;
        
        require(positionDebtValue > collateralValue, "LiquidationProtector/position-not-at-risk");
        
        // Calculate and collect protection fee
        uint256 protectionFee = calculateProtectionFee(_collateralPoolId, positionDebtValue);
        require(msg.value >= protectionFee, "LiquidationProtector/insufficient-fee");
        
        // Create protection request
        protectionRequests[_collateralPoolId][_positionAddress] = ProtectionRequest({
            collateralPoolId: _collateralPoolId,
            positionAddress: _positionAddress,
            requestTimestamp: block.timestamp,
            originalDebt: positionDebtValue,
            originalCollateral: lockedCollateral,
            targetHealthRatio: _targetHealthRatio,
            isActive: true
        });
        
        // Transfer fee
        if (protectionFee > 0) {
            payable(feeRecipient).transfer(protectionFee);
            totalFeesCollected[feeRecipient] += protectionFee;
        }
        
        // Refund excess payment
        if (msg.value > protectionFee) {
            payable(msg.sender).transfer(msg.value - protectionFee);
        }
        
        emit LogProtectionRequested(
            _collateralPoolId,
            _positionAddress,
            block.timestamp + gracePeriod,
            _targetHealthRatio
        );
        
        return true;
    }

    function executeProtection(
        bytes32 _collateralPoolId,
        address _positionAddress,
        uint256 _collateralToAdd,
        uint256 _debtToReduce
    ) external override nonReentrant whenNotPaused returns (bool) {
        ProtectionRequest storage request = protectionRequests[_collateralPoolId][_positionAddress];
        require(request.isActive, "LiquidationProtector/no-active-protection");
        require(block.timestamp <= request.requestTimestamp + gracePeriod, "LiquidationProtector/protection-expired");
        require(msg.sender == _positionAddress, "LiquidationProtector/unauthorized");
        require(_collateralToAdd > 0 || _debtToReduce > 0, "LiquidationProtector/no-action-specified");
        
        // Get current position state
        (uint256 currentCollateral, uint256 currentDebtShare) = bookKeeper.positions(_collateralPoolId, _positionAddress);
        ICollateralPoolConfig.CollateralPoolInfo memory poolInfo = 
            ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getCollateralPoolInfo(_collateralPoolId);
        
        uint256 currentDebtValue = currentDebtShare * poolInfo.debtAccumulatedRate;
        
        // Calculate projected health ratio after protection actions
        uint256 projectedCollateral = currentCollateral + _collateralToAdd;
        uint256 projectedDebtValue = currentDebtValue >= _debtToReduce ? currentDebtValue - _debtToReduce : 0;
        
        uint256 projectedCollateralValue = projectedCollateral * poolInfo.priceWithSafetyMargin;
        uint256 healthRatio = projectedDebtValue > 0 ? (projectedCollateralValue * RAY) / projectedDebtValue : type(uint256).max;
        
        require(healthRatio >= request.targetHealthRatio, "LiquidationProtector/insufficient-improvement");
        
        bool success = true;
        
        // Execute protection actions through position manager
        // Note: This would require integration with PositionManager for actual execution
        // For now, we validate the request and mark it as executed
        
        // Deactivate protection
        request.isActive = false;
        
        emit LogProtectionExecuted(_collateralPoolId, _positionAddress, _collateralToAdd, _debtToReduce, success);
        
        return success;
    }

    function cancelProtection(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external override nonReentrant returns (bool) {
        ProtectionRequest storage request = protectionRequests[_collateralPoolId][_positionAddress];
        require(request.isActive, "LiquidationProtector/no-active-protection");
        require(msg.sender == _positionAddress || 
                accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender),
                "LiquidationProtector/unauthorized");
        
        request.isActive = false;
        
        emit LogProtectionExpired(_collateralPoolId, _positionAddress);
        
        return true;
    }

    function isPositionProtected(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) public view override returns (bool) {
        ProtectionRequest memory request = protectionRequests[_collateralPoolId][_positionAddress];
        
        if (!request.isActive) {
            return false;
        }
        
        // Check if protection has expired
        if (block.timestamp > request.requestTimestamp + gracePeriod) {
            return false;
        }
        
        return true;
    }

    function getProtectionInfo(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external view override returns (ProtectionRequest memory) {
        return protectionRequests[_collateralPoolId][_positionAddress];
    }

    function canExecuteLiquidation(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external view override returns (bool) {
        // Liquidation can proceed if position is not protected
        return !isPositionProtected(_collateralPoolId, _positionAddress);
    }

    function calculateProtectionFee(
        bytes32 _collateralPoolId,
        uint256 _positionDebt
    ) public view override returns (uint256) {
        // Fee is proportional to debt size and risk level
        ICollateralPoolConfig.CollateralPoolInfo memory poolInfo = 
            ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getCollateralPoolInfo(_collateralPoolId);
        
        // Base fee: 0.1% of debt value
        uint256 baseFee = (_positionDebt * 1e15) / RAY; // Convert from RAD to WAD and apply 0.1%
        
        // Risk multiplier based on liquidation ratio
        uint256 liquidationRatio = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getLiquidationRatio(_collateralPoolId);
        uint256 riskMultiplier = liquidationRatio > RAY ? ((liquidationRatio - RAY) * 2) + RAY : RAY;
        
        uint256 totalFee = (baseFee * riskMultiplier) / RAY;
        
        // Cap at maximum protection fee
        uint256 maxFee = (_positionDebt * maxProtectionFee) / (RAY * FEE_PRECISION);
        
        return totalFee > maxFee ? maxFee : totalFee;
    }

    function setGracePeriod(uint256 _newGracePeriod) external override onlyOwner {
        require(_newGracePeriod >= MIN_GRACE_PERIOD && _newGracePeriod <= MAX_GRACE_PERIOD, "LiquidationProtector/invalid-grace-period");
        uint256 oldPeriod = gracePeriod;
        gracePeriod = _newGracePeriod;
        emit LogGracePeriodUpdated(oldPeriod, _newGracePeriod);
    }

    function setMaxProtectionFee(uint256 _newMaxFee) external override onlyOwner {
        require(_newMaxFee <= MAX_PROTECTION_FEE, "LiquidationProtector/invalid-max-fee");
        uint256 oldFee = maxProtectionFee;
        maxProtectionFee = _newMaxFee;
        emit LogMaxProtectionFeeUpdated(oldFee, _newMaxFee);
    }

    function setFeeRecipient(address _newFeeRecipient) external onlyOwner {
        require(_newFeeRecipient != address(0), "LiquidationProtector/invalid-fee-recipient");
        feeRecipient = _newFeeRecipient;
    }

    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    // Emergency function to clean up expired protections
    function cleanupExpiredProtection(
        bytes32 _collateralPoolId,
        address _positionAddress
    ) external {
        ProtectionRequest storage request = protectionRequests[_collateralPoolId][_positionAddress];
        require(request.isActive, "LiquidationProtector/no-active-protection");
        require(block.timestamp > request.requestTimestamp + gracePeriod, "LiquidationProtector/protection-not-expired");
        
        request.isActive = false;
        emit LogProtectionExpired(_collateralPoolId, _positionAddress);
    }

    // View function for analytics
    function getActiveProtectionsCount() external view returns (uint256) {
        // This would need to be implemented with additional storage if needed for monitoring
        return 0; // Placeholder
    }
}
