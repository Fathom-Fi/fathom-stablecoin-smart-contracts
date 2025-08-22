// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../interfaces/IEmergencyCoordinator.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../utils/CommonMath.sol";

/**
 * @title EmergencyCoordinator
 * @notice Provides graduated emergency response capabilities with different restriction levels
 * instead of binary pause/unpause functionality
 */
contract EmergencyCoordinator is 
    CommonMath,
    ReentrancyGuardUpgradeable, 
    IEmergencyCoordinator 
{
    uint256 public constant MIN_EMERGENCY_DURATION = 1 hours;
    uint256 public constant MAX_EMERGENCY_DURATION = 30 days;
    uint256 public constant AUTO_RESOLUTION_BUFFER = 15 minutes;
    
    IBookKeeper public bookKeeper;
    IAccessControlConfig public accessControlConfig;
    
    mapping(bytes32 => EmergencyAction) public emergencies;
    mapping(EmergencyLevel => RestrictionsConfig) public levelRestrictions;
    mapping(address => bool) public authorizedResponders;
    
    bytes32[] public activeEmergencyIds;
    EmergencyLevel public currentEmergencyLevel;
    
    uint256 public nextEmergencyId;
    bool public autoResolutionEnabled;
    uint256 public minEmergencyDuration;
    uint256 public maxEmergencyDuration;

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
                authorizedResponders[msg.sender],
            "!authorizedResponder"
        );
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _bookKeeper,
        bool _autoResolutionEnabled
    ) external initializer {
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        
        require(_bookKeeper != address(0), "EmergencyCoordinator/invalid-bookkeeper");
        
        bookKeeper = IBookKeeper(_bookKeeper);
        accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        
        autoResolutionEnabled = _autoResolutionEnabled;
        minEmergencyDuration = MIN_EMERGENCY_DURATION;
        maxEmergencyDuration = MAX_EMERGENCY_DURATION;
        nextEmergencyId = 1;
        
        // Initialize default restrictions for each level
        _initializeDefaultRestrictions();
    }

    function _initializeDefaultRestrictions() internal {
        // NORMAL - No restrictions
        levelRestrictions[EmergencyLevel.NORMAL] = RestrictionsConfig({
            maxMintAmount: type(uint256).max,
            maxWithdrawAmount: type(uint256).max,
            maxLiquidationSize: type(uint256).max,
            delayPeriod: 0,
            mintingEnabled: true,
            liquidationEnabled: true,
            transfersEnabled: true,
            flashLoansEnabled: true
        });

        // LEVEL_1 - Minor restrictions
        levelRestrictions[EmergencyLevel.LEVEL_1] = RestrictionsConfig({
            maxMintAmount: 1000000e18, // 1M tokens
            maxWithdrawAmount: 1000000e18,
            maxLiquidationSize: 500000e18,
            delayPeriod: 10 minutes,
            mintingEnabled: true,
            liquidationEnabled: true,
            transfersEnabled: true,
            flashLoansEnabled: true
        });

        // LEVEL_2 - Moderate restrictions
        levelRestrictions[EmergencyLevel.LEVEL_2] = RestrictionsConfig({
            maxMintAmount: 100000e18, // 100K tokens
            maxWithdrawAmount: 500000e18,
            maxLiquidationSize: 100000e18,
            delayPeriod: 30 minutes,
            mintingEnabled: true,
            liquidationEnabled: true,
            transfersEnabled: true,
            flashLoansEnabled: false
        });

        // LEVEL_3 - Severe restrictions
        levelRestrictions[EmergencyLevel.LEVEL_3] = RestrictionsConfig({
            maxMintAmount: 0, // No new minting
            maxWithdrawAmount: 100000e18,
            maxLiquidationSize: 50000e18,
            delayPeriod: 1 hours,
            mintingEnabled: false,
            liquidationEnabled: true,
            transfersEnabled: true,
            flashLoansEnabled: false
        });

        // CRITICAL - Complete shutdown except emergency withdrawals
        levelRestrictions[EmergencyLevel.CRITICAL] = RestrictionsConfig({
            maxMintAmount: 0,
            maxWithdrawAmount: 10000e18, // Emergency withdrawals only
            maxLiquidationSize: 0,
            delayPeriod: 0, // No delays for emergency operations
            mintingEnabled: false,
            liquidationEnabled: false,
            transfersEnabled: false,
            flashLoansEnabled: false
        });
    }

    function declareEmergency(
        EmergencyLevel _level,
        EmergencyType _type,
        uint256 _duration,
        string calldata _description
    ) external override nonReentrant onlyAuthorized returns (bytes32 emergencyId) {
        require(_level > EmergencyLevel.NORMAL, "EmergencyCoordinator/invalid-level");
        require(_duration >= minEmergencyDuration && _duration <= maxEmergencyDuration, 
                "EmergencyCoordinator/invalid-duration");
        
        emergencyId = bytes32(nextEmergencyId++);
        
        emergencies[emergencyId] = EmergencyAction({
            level: _level,
            emergencyType: _type,
            initiator: msg.sender,
            timestamp: block.timestamp,
            duration: _duration,
            description: _description,
            isActive: true,
            isResolved: false
        });
        
        activeEmergencyIds.push(emergencyId);
        
        // Update system emergency level to highest active level
        _updateSystemEmergencyLevel();
        
        emit LogEmergencyDeclared(emergencyId, _level, _type, msg.sender, _description);
        return emergencyId;
    }

    function resolveEmergency(bytes32 _emergencyId) external override nonReentrant onlyAuthorized returns (bool) {
        EmergencyAction storage emergency = emergencies[_emergencyId];
        require(emergency.isActive && !emergency.isResolved, "EmergencyCoordinator/invalid-emergency");
        
        // Check if minimum duration has passed (except for CRITICAL level)
        if (emergency.level != EmergencyLevel.CRITICAL) {
            require(block.timestamp >= emergency.timestamp + minEmergencyDuration, 
                    "EmergencyCoordinator/min-duration-not-met");
        }
        
        emergency.isActive = false;
        emergency.isResolved = true;
        
        // Remove from active emergencies
        _removeFromActiveEmergencies(_emergencyId);
        
        // Update system emergency level
        _updateSystemEmergencyLevel();
        
        emit LogEmergencyResolved(_emergencyId, emergency.level, msg.sender);
        return true;
    }

    function escalateEmergency(bytes32 _emergencyId, EmergencyLevel _newLevel) external override nonReentrant onlyAuthorized returns (bool) {
        EmergencyAction storage emergency = emergencies[_emergencyId];
        require(emergency.isActive, "EmergencyCoordinator/emergency-not-active");
        require(_newLevel > emergency.level, "EmergencyCoordinator/cannot-de-escalate");
        
        EmergencyLevel oldLevel = emergency.level;
        emergency.level = _newLevel;
        
        // Update system emergency level
        _updateSystemEmergencyLevel();
        
        emit LogEmergencyLevelChanged(_emergencyId, oldLevel, _newLevel);
        return true;
    }

    function getCurrentEmergencyLevel() external view override returns (EmergencyLevel) {
        return currentEmergencyLevel;
    }

    function isOperationAllowed(bytes4 _functionSelector) external view override returns (bool) {
        RestrictionsConfig memory restrictions = levelRestrictions[currentEmergencyLevel];
        
        // Map function selectors to restrictions
        if (_functionSelector == bytes4(keccak256("mint(address,uint256)"))) {
            return restrictions.mintingEnabled;
        } else if (_functionSelector == bytes4(keccak256("liquidate(bytes32,address,uint256,uint256,address,bytes)"))) {
            return restrictions.liquidationEnabled;
        } else if (_functionSelector == bytes4(keccak256("transfer(address,uint256)"))) {
            return restrictions.transfersEnabled;
        } else if (_functionSelector == bytes4(keccak256("flashLoan(address,address,uint256,bytes)"))) {
            return restrictions.flashLoansEnabled;
        }
        
        // Default: allow operation if not specifically restricted
        return true;
    }

    function isAmountAllowed(
        bytes4 _functionSelector,
        uint256 _amount
    ) external view override returns (bool) {
        RestrictionsConfig memory restrictions = levelRestrictions[currentEmergencyLevel];
        
        if (_functionSelector == bytes4(keccak256("mint(address,uint256)"))) {
            return _amount <= restrictions.maxMintAmount;
        } else if (_functionSelector == bytes4(keccak256("withdraw(uint256)"))) {
            return _amount <= restrictions.maxWithdrawAmount;
        } else if (_functionSelector == bytes4(keccak256("liquidate(bytes32,address,uint256,uint256,address,bytes)"))) {
            return _amount <= restrictions.maxLiquidationSize;
        }
        
        return true; // No restrictions for other operations
    }

    function getActiveEmergencies() external view override returns (bytes32[] memory) {
        return activeEmergencyIds;
    }

    function getEmergencyInfo(bytes32 _emergencyId) external view override returns (EmergencyAction memory) {
        return emergencies[_emergencyId];
    }

    function getRestrictionsForLevel(EmergencyLevel _level) external view override returns (RestrictionsConfig memory) {
        return levelRestrictions[_level];
    }

    function _updateSystemEmergencyLevel() internal {
        EmergencyLevel highestLevel = EmergencyLevel.NORMAL;
        
        // Find the highest active emergency level
        for (uint256 i = 0; i < activeEmergencyIds.length; i++) {
            EmergencyAction storage emergency = emergencies[activeEmergencyIds[i]];
            if (emergency.isActive && emergency.level > highestLevel) {
                highestLevel = emergency.level;
            }
        }
        
        // Check for auto-resolution
        if (autoResolutionEnabled) {
            _checkAutoResolution();
        }
        
        currentEmergencyLevel = highestLevel;
    }

    function _checkAutoResolution() internal {
        for (uint256 i = 0; i < activeEmergencyIds.length; i++) {
            bytes32 emergencyId = activeEmergencyIds[i];
            EmergencyAction storage emergency = emergencies[emergencyId];
            
            if (emergency.isActive && emergency.duration > 0) {
                uint256 expirationTime = emergency.timestamp + emergency.duration;
                if (block.timestamp >= expirationTime + AUTO_RESOLUTION_BUFFER) {
                    emergency.isActive = false;
                    emergency.isResolved = true;
                    emit LogEmergencyResolved(emergencyId, emergency.level, address(this));
                }
            }
        }
        
        // Clean up resolved emergencies from active list
        _cleanupResolvedEmergencies();
    }

    function _removeFromActiveEmergencies(bytes32 _emergencyId) internal {
        for (uint256 i = 0; i < activeEmergencyIds.length; i++) {
            if (activeEmergencyIds[i] == _emergencyId) {
                activeEmergencyIds[i] = activeEmergencyIds[activeEmergencyIds.length - 1];
                activeEmergencyIds.pop();
                break;
            }
        }
    }

    function _cleanupResolvedEmergencies() internal {
        uint256 writeIndex = 0;
        for (uint256 readIndex = 0; readIndex < activeEmergencyIds.length; readIndex++) {
            if (emergencies[activeEmergencyIds[readIndex]].isActive) {
                activeEmergencyIds[writeIndex] = activeEmergencyIds[readIndex];
                writeIndex++;
            }
        }
        
        // Trim the array
        while (activeEmergencyIds.length > writeIndex) {
            activeEmergencyIds.pop();
        }
    }

    function setRestrictions(
        EmergencyLevel _level,
        RestrictionsConfig calldata _restrictions
    ) external override onlyOwner {
        require(_level != EmergencyLevel.NORMAL || 
                (_restrictions.mintingEnabled && _restrictions.liquidationEnabled && 
                 _restrictions.transfersEnabled && _restrictions.flashLoansEnabled),
                "EmergencyCoordinator/cannot-restrict-normal-level");
        
        levelRestrictions[_level] = _restrictions;
        emit LogRestrictionsUpdated(_level, _restrictions);
    }

    function addAuthorizedResponder(address _responder) external override onlyOwner {
        require(_responder != address(0), "EmergencyCoordinator/invalid-responder");
        require(!authorizedResponders[_responder], "EmergencyCoordinator/already-authorized");
        
        authorizedResponders[_responder] = true;
        emit LogAuthorizedResponderAdded(_responder);
    }

    function removeAuthorizedResponder(address _responder) external override onlyOwner {
        require(authorizedResponders[_responder], "EmergencyCoordinator/not-authorized");
        
        authorizedResponders[_responder] = false;
        emit LogAuthorizedResponderRemoved(_responder);
    }

    function isAuthorizedResponder(address _responder) external view override returns (bool) {
        return authorizedResponders[_responder] ||
               accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), _responder) ||
               accessControlConfig.hasRole(accessControlConfig.GOV_ROLE(), _responder);
    }

    function setAutoResolution(bool _enabled) external override onlyOwner {
        autoResolutionEnabled = _enabled;
    }

    function setMinEmergencyDuration(uint256 _duration) external override onlyOwner {
        require(_duration >= 5 minutes && _duration <= maxEmergencyDuration, 
                "EmergencyCoordinator/invalid-min-duration");
        minEmergencyDuration = _duration;
    }

    function setMaxEmergencyDuration(uint256 _duration) external override onlyOwner {
        require(_duration >= minEmergencyDuration && _duration <= 90 days, 
                "EmergencyCoordinator/invalid-max-duration");
        maxEmergencyDuration = _duration;
    }

    // Public function to trigger auto-resolution check
    function checkAutoResolution() external {
        if (autoResolutionEnabled) {
            _checkAutoResolution();
            _updateSystemEmergencyLevel();
        }
    }

    // Emergency function to force resolve all emergencies (only owner)
    function forceResolveAllEmergencies() external onlyOwner {
        for (uint256 i = 0; i < activeEmergencyIds.length; i++) {
            bytes32 emergencyId = activeEmergencyIds[i];
            EmergencyAction storage emergency = emergencies[emergencyId];
            if (emergency.isActive) {
                emergency.isActive = false;
                emergency.isResolved = true;
                emit LogEmergencyResolved(emergencyId, emergency.level, msg.sender);
            }
        }
        
        delete activeEmergencyIds;
        currentEmergencyLevel = EmergencyLevel.NORMAL;
    }
}
