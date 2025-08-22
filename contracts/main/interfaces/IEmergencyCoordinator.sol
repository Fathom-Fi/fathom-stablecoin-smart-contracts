// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

interface IEmergencyCoordinator {
    enum EmergencyLevel {
        NORMAL,          // 0 - Normal operations
        LEVEL_1,         // 1 - Minor restrictions (reduce limits)
        LEVEL_2,         // 2 - Moderate restrictions (pause non-critical functions)
        LEVEL_3,         // 3 - Severe restrictions (emergency withdrawals only)
        CRITICAL         // 4 - Complete shutdown
    }

    enum EmergencyType {
        MARKET_VOLATILITY,
        ORACLE_FAILURE,
        SMART_CONTRACT_BUG,
        GOVERNANCE_ATTACK,
        ECONOMIC_EXPLOIT,
        EXTERNAL_DEPENDENCY_FAILURE,
        REGULATORY_ACTION
    }

    struct EmergencyAction {
        EmergencyLevel level;
        EmergencyType emergencyType;
        address initiator;
        uint256 timestamp;
        uint256 duration; // Auto-resolution time (0 = manual resolution required)
        string description;
        bool isActive;
        bool isResolved;
    }

    struct RestrictionsConfig {
        uint256 maxMintAmount;        // Maximum single mint amount
        uint256 maxWithdrawAmount;    // Maximum single withdrawal amount
        uint256 maxLiquidationSize;   // Maximum liquidation size
        uint256 delayPeriod;         // Delay for critical operations
        bool mintingEnabled;         // Whether minting is allowed
        bool liquidationEnabled;     // Whether liquidations are allowed
        bool transfersEnabled;       // Whether transfers are allowed
        bool flashLoansEnabled;      // Whether flash loans are allowed
    }

    event LogEmergencyDeclared(
        bytes32 indexed emergencyId,
        EmergencyLevel level,
        EmergencyType emergencyType,
        address indexed initiator,
        string description
    );
    
    event LogEmergencyResolved(
        bytes32 indexed emergencyId,
        EmergencyLevel level,
        address indexed resolver
    );
    
    event LogEmergencyLevelChanged(
        bytes32 indexed emergencyId,
        EmergencyLevel oldLevel,
        EmergencyLevel newLevel
    );
    
    event LogRestrictionsUpdated(EmergencyLevel level, RestrictionsConfig restrictions);
    event LogAuthorizedResponderAdded(address indexed responder);
    event LogAuthorizedResponderRemoved(address indexed responder);

    function declareEmergency(
        EmergencyLevel _level,
        EmergencyType _type,
        uint256 _duration,
        string calldata _description
    ) external returns (bytes32 emergencyId);

    function resolveEmergency(bytes32 _emergencyId) external returns (bool);
    
    function escalateEmergency(bytes32 _emergencyId, EmergencyLevel _newLevel) external returns (bool);
    
    function getCurrentEmergencyLevel() external view returns (EmergencyLevel);
    
    function isOperationAllowed(bytes4 _functionSelector) external view returns (bool);
    
    function isAmountAllowed(
        bytes4 _functionSelector,
        uint256 _amount
    ) external view returns (bool);
    
    function getActiveEmergencies() external view returns (bytes32[] memory);
    
    function getEmergencyInfo(bytes32 _emergencyId) external view returns (EmergencyAction memory);
    
    function getRestrictionsForLevel(EmergencyLevel _level) external view returns (RestrictionsConfig memory);
    
    function setRestrictions(
        EmergencyLevel _level,
        RestrictionsConfig calldata _restrictions
    ) external;
    
    function addAuthorizedResponder(address _responder) external;
    function removeAuthorizedResponder(address _responder) external;
    function isAuthorizedResponder(address _responder) external view returns (bool);
    
    function setAutoResolution(bool _enabled) external;
    function setMinEmergencyDuration(uint256 _duration) external;
    function setMaxEmergencyDuration(uint256 _duration) external;
}
