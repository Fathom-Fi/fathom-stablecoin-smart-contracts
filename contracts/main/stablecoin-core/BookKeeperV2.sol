// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/ICagable.sol";
import "../interfaces/ICollateralPoolConfig.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../interfaces/IPausable.sol";
import "../utils/CommonMath.sol";

/**
 * @title BookKeeper
 * @notice A contract which acts as a bookkeeper of the Fathom Stablecoin protocol.
 * It has the ability to move collateral tokens and stablecoins within the accounting state variable.
 */
contract BookKeeperV2 is IBookKeeper, ICagable, IPausable, CommonMath, PausableUpgradeable, ReentrancyGuardUpgradeable {
    using AddressUpgradeable for address;

    struct Position {
        uint256 lockedCollateral; // Locked collateral inside this position (used for minting)                  [wad]
        uint256 debtShare; // The debt share of this position or the share amount of minted Fathom Stablecoin   [wad]
    }

    mapping(bytes32 => mapping(address => Position)) public override positions; // mapping of all positions by collateral pool id and position address
    mapping(bytes32 => mapping(address => uint256)) public override collateralToken; // the accounting of collateral token which is deposited into the protocol [wad]
    mapping(address => uint256) public override stablecoin; // the accounting of the stablecoin that is deposited or has not been withdrawn from the protocol [rad]
    mapping(address => uint256) public override systemBadDebt; // the bad debt of the system from late liquidation [rad]
    mapping(bytes32 => uint256) public override poolStablecoinIssued; // the accounting of the stablecoin issued per collateralPool [rad];

    /// @dev This is the mapping which stores the consent or allowance to adjust positions by the position addresses.
    /// @dev The position address -> The allowance delegate address -> true (1) means allowed or false (0) means not allowed
    mapping(address => mapping(address => uint256)) public override positionWhitelist;

    uint256 public override totalStablecoinIssued; // Total stable coin issued or total stablecoin in circulation   [rad]
    uint256 public totalUnbackedStablecoin; // Total unbacked stable coin  [rad]
    uint256 public totalDebtCeiling; // Total debt ceiling  [rad]
    uint256 public live; // Active Flag
    address public override collateralPoolConfig;
    address public override accessControlConfig;

    event LogSetTotalDebtCeiling(address indexed _caller, uint256 _totalDebtCeiling);
    event LogSetAccessControlConfig(address indexed _caller, address _accessControlConfig);
    event LogSetCollateralPoolConfig(address indexed _caller, address _collateralPoolConfig);
    event LogAdjustPosition(
        address indexed _caller,
        bytes32 indexed _collateralPoolId,
        address indexed _positionAddress,
        uint256 _lockedCollateral,
        uint256 _debtShare,
        uint256 _positionDebtValue,
        int256 _addCollateral,
        int256 _addDebtShare
    );
    event LogAddCollateral(address indexed _caller, address indexed _usr, int256 _amount);
    event LogMoveCollateral(address indexed _caller, bytes32 indexed _collateralPoolId, address _src, address indexed _dst, uint256 _amount);
    event LogMoveStablecoin(address indexed _caller, address _src, address indexed _dst, uint256 _amount);
    event LogAddToWhitelist(address indexed _user);
    event LogRemoveFromWhitelist(address indexed _user);
    event StablecoinIssuedAmount(uint256 _totalStablecoinIssued, bytes32 indexed _collateralPoolId, uint256 _poolStablecoinIssued);

    modifier onlyOwner() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender), "!ownerRole");
        _;
    }

    modifier onlyOwnerOrGov() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(
            _accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender) ||
                _accessControlConfig.hasRole(_accessControlConfig.GOV_ROLE(), msg.sender),
            "!(ownerRole or govRole)"
        );
        _;
    }

    modifier onlyOwnerOrShowStopper() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(
            _accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender) ||
                _accessControlConfig.hasRole(_accessControlConfig.SHOW_STOPPER_ROLE(), msg.sender),
            "!(ownerRole or showStopperRole)"
        );
        _;
    }

    modifier onlyPositionManager() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.POSITION_MANAGER_ROLE(), msg.sender), "!positionManagerRole");
        _;
    }

    modifier onlyCollateralManager() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.COLLATERAL_MANAGER_ROLE(), msg.sender), "!collateralManagerRole");
        _;
    }

    modifier onlyLiquidationEngine() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.LIQUIDATION_ENGINE_ROLE(), msg.sender), "!liquidationEngineRole");
        _;
    }

    modifier onlyMintable() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.MINTABLE_ROLE(), msg.sender), "!mintableRole");
        _;
    }

    modifier onlyAdapter() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.ADAPTER_ROLE(), msg.sender), "!adapterRole");
        _;
    }

    modifier onlyStabilityFeeCollector() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(accessControlConfig);
        require(_accessControlConfig.hasRole(_accessControlConfig.STABILITY_FEE_COLLECTOR_ROLE(), msg.sender), "!stabilityFeeCollectorRole");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    // --- Init ---

    function initialize(address _collateralPoolConfig, address _accessControlConfig) external initializer {
        require(_collateralPoolConfig.isContract(), "BookKeeper/collateral-pool-config: NOT_CONTRACT_ADDRESS");
        require(_accessControlConfig.isContract(), "BookKeeper/access-control-config: NOT_CONTRACT_ADDRESS");
        require(
            IAccessControlConfig(_accessControlConfig).hasRole(IAccessControlConfig(_accessControlConfig).OWNER_ROLE(), msg.sender),
            "BookKeeper/msgsender-not-owner"
        ); // Sanity Check Call

        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        collateralPoolConfig = _collateralPoolConfig;
        accessControlConfig = _accessControlConfig;
        live = 1;
    }

    // --- Administration ---
    /// @dev Sets the total debt ceiling of the entire protocol. The totalDebtCeiling is the maximum amount of debt that can be borrowed from the protocol.
    /// @param _totalDebtCeiling The new total debt ceiling value to be set.
    function setTotalDebtCeiling(uint256 _totalDebtCeiling) external onlyOwner {
        _requireLive();
        totalDebtCeiling = _totalDebtCeiling;
        emit LogSetTotalDebtCeiling(msg.sender, _totalDebtCeiling);
    }

    function setAccessControlConfig(address _accessControlConfig) external onlyOwner {
        require(_accessControlConfig.isContract(), "BookKeeper/access-control-config: NOT_CONTRACT_ADDRESS");
        require(
            IAccessControlConfig(_accessControlConfig).hasRole(IAccessControlConfig(_accessControlConfig).OWNER_ROLE(), msg.sender),
            "BookKeeper/msgsender-not-owner"
        );
        accessControlConfig = _accessControlConfig;
        emit LogSetAccessControlConfig(msg.sender, _accessControlConfig);
    }

    function setCollateralPoolConfig(address _collateralPoolConfig) external onlyOwner {
        require(_collateralPoolConfig.isContract(), "BookKeeper/collateral-pool-config: NOT_CONTRACT_ADDRESS");

        collateralPoolConfig = _collateralPoolConfig;
        emit LogSetCollateralPoolConfig(msg.sender, _collateralPoolConfig);
    }

    // --- Cage ---
    /// @dev Cage function halts bookKeeper contract for good.
    /// Please be cautious with this function since there is no uncage function
    function cage() external override onlyOwnerOrShowStopper {
        if (live == 1) {
            live = 0;
            emit LogCage();
        }
    }

    // --- Pause ---
    /// @dev access: OWNER_ROLE, GOV_ROLE
    function pause() external override onlyOwnerOrGov {
        _pause();
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function unpause() external override onlyOwnerOrGov {
        _unpause();
    }

    // --- Whitelist ---

    /// @dev Grants an allowance to the `toBeWhitelistedAddress` to adjust the position address of the caller.
    /// @notice This function can only be called when the BookKeeper contract is not paused.
    /// @param _toBeWhitelistedAddress The address that is granted permission to adjust the position address of the caller.
    /// @dev Emits no events.
    function whitelist(address _toBeWhitelistedAddress) external override whenNotPaused {
        positionWhitelist[msg.sender][_toBeWhitelistedAddress] = 1;
        emit LogAddToWhitelist(_toBeWhitelistedAddress);
    }

    /// @dev Revokes the allowance from the `toBeRemovedAddress` to adjust the position address of the caller.
    /// @notice This function can only be called when the BookKeeper contract is not paused.
    /// @param _toBeRemovedAddress The address that is no longer allowed to adjust the position address of the caller.
    /// @dev Emits no events.
    function removeFromWhitelist(address _toBeRemovedAddress) external override whenNotPaused {
        positionWhitelist[msg.sender][_toBeRemovedAddress] = 0;
        emit LogRemoveFromWhitelist(_toBeRemovedAddress);
    }

    // --- Core Logic ---

    /// @dev Updates the accounting of collateral tokens deposited by a position in the specified collateral pool.
    /// @dev Although the second argument is named as _usr, addCollateral is more often used in the context of CDP manipulation, and the _usr address
    /// often represents the position's address. Refer to deposit function in CollateralTokenAdapter.
    /// @notice This function can only be called by the Adapter role when the BookKeeper contract is not paused.
    /// @param _collateralPoolId The ID of the collateral pool in which the position's collateral is being updated.
    /// @param _usr The address of the position for which collateral is being adjusted.
    /// @param _amount The amount of collateral being added (positive value) or removed (negative value) from the user's position.
    /// @dev Emits a LogAddCollateral event to record the change in the position's collateral amount.
    function addCollateral(bytes32 _collateralPoolId, address _usr, int256 _amount) external override nonReentrant whenNotPaused onlyAdapter {
        collateralToken[_collateralPoolId][_usr] = add(collateralToken[_collateralPoolId][_usr], _amount);
        emit LogAddCollateral(msg.sender, _usr, _amount);
    }

    /// @notice Moves collateral tokens from one address (often a position address) to another in a specified collateral pool.
    /// @dev This function can only be called by an entity with the Collateral Manager role when the BookKeeper contract is not paused.
    /// @dev It also requires that the entity making the call has the authority to adjust the position (or any address that holds collateralToken),
    ///      as determined by `_requireAllowedPositionAdjustment`.
    /// @param _collateralPoolId The ID of the collateral pool from which the collateral tokens are being moved.
    /// @param _src The address from which collateral tokens are being moved.
    /// @param _dst The address to which collateral tokens are being moved.
    /// @param _amount The amount of collateral tokens being moved from the source to the destination.

    function moveCollateral(
        bytes32 _collateralPoolId,
        address _src,
        address _dst,
        uint256 _amount
    ) external override nonReentrant whenNotPaused onlyCollateralManager {
        require(_amount > 0, "bookKeeper/moveCollateral-zero-amount");
        require(_src != _dst, "bookKeeper/moveCollateral-src-dst-same");
        _requireAllowedPositionAdjustment(_src, msg.sender);
        collateralToken[_collateralPoolId][_src] -= _amount;
        collateralToken[_collateralPoolId][_dst] += _amount;
        emit LogMoveCollateral(msg.sender, _collateralPoolId, _src, _dst, _amount);
    }

    /// @notice Moves stablecoin from one address to another.
    /// @dev This function can only be called when the BookKeeper contract is not paused.
    /// @dev It also requires that the entity making the call is allowed to adjust the position (or any address that holds stablecoin)
    /// @dev according to `_requireAllowedPositionAdjustment`.
    /// @param _src The source address from which the stablecoin is being moved.
    /// @param _dst The destination address to which the stablecoin is being moved.
    /// @param _value The amount of stablecoin being moved from the source to the destination.

    function moveStablecoin(address _src, address _dst, uint256 _value) external override nonReentrant whenNotPaused {
        require(_value > 0, "bookKeeper/moveStablecoin-zero-amount");
        require(_src != _dst, "bookKeeper/moveStablecoin-src-dst-same");
        _requireAllowedPositionAdjustment(_src, msg.sender);
        stablecoin[_src] -= _value;
        stablecoin[_dst] += _value;
        emit LogMoveStablecoin(msg.sender, _src, _dst, _value);
    }

    /// @notice Adjusts the collateral and debt of a position in a specific collateral pool.
    /// @dev This function can only be called by an entity with the Position Manager role when the BookKeeper contract is not paused and the collateral pool is active.
    /// @dev It ensures multiple conditions are met regarding debt and collateral values to maintain system stability and safety.
    /// @param _collateralPoolId The ID of the collateral pool where the position is located.
    /// @param _positionAddress The address of the position to be adjusted.
    /// @param _collateralOwner The address of the owner of the collateral. (positionAddress)
    /// @param _stablecoinOwner The address of the owner of the stablecoin. (positionAddress)
    /// @param _collateralValue The change in collateral value. This is added to the position's current locked collateral.
    /// @param _debtShare The change in debt share. This is added to the position's current debt share.
    // solhint-disable function-max-lines
    function adjustPosition(
        bytes32 _collateralPoolId,
        address _positionAddress,
        address _collateralOwner,
        address _stablecoinOwner,
        int256 _collateralValue,
        int256 _debtShare
    ) external override nonReentrant whenNotPaused onlyPositionManager {
        _requireLive();

        ICollateralPoolConfig.CollateralPoolInfo memory _vars = ICollateralPoolConfig(collateralPoolConfig).getCollateralPoolInfo(_collateralPoolId);
        require(_vars.debtAccumulatedRate != 0, "BookKeeper/collateralPool-not-init");

        Position memory position = positions[_collateralPoolId][_positionAddress];
        position.lockedCollateral = add(position.lockedCollateral, _collateralValue);
        position.debtShare = add(position.debtShare, _debtShare);
        _vars.totalDebtShare = add(_vars.totalDebtShare, _debtShare);
        ICollateralPoolConfig(collateralPoolConfig).setTotalDebtShare(_collateralPoolId, _vars.totalDebtShare);

        int256 _debtValue = mul(_vars.debtAccumulatedRate, _debtShare);
        uint256 _positionDebtValue = _vars.debtAccumulatedRate * position.debtShare;
        totalStablecoinIssued = add(totalStablecoinIssued, _debtValue);
        uint256 _poolStablecoinAmount = poolStablecoinIssued[_collateralPoolId];
        poolStablecoinIssued[_collateralPoolId] = add(_poolStablecoinAmount, _debtValue);
        _poolStablecoinAmount = poolStablecoinIssued[_collateralPoolId];
        require(
            either(
                _debtShare <= 0,
                both(_vars.totalDebtShare * _vars.debtAccumulatedRate <= _vars.debtCeiling, totalStablecoinIssued <= totalDebtCeiling)
            ),
            "BookKeeper/ceiling-exceeded"
        );

        require(
            either(both(_debtShare <= 0, _collateralValue >= 0), _positionDebtValue <= position.lockedCollateral * _vars.priceWithSafetyMargin),
            "BookKeeper/not-safe"
        );

        require(either(both(_debtShare <= 0, _collateralValue >= 0), _wish(_positionAddress, msg.sender)), "BookKeeper/not-allowed-position-address");
        require(either(_collateralValue <= 0, _wish(_collateralOwner, msg.sender)), "BookKeeper/not-allowed-collateral-owner");
        require(either(_debtShare >= 0, _wish(_stablecoinOwner, msg.sender)), "BookKeeper/not-allowed-stablecoin-owner");

        require(either(position.debtShare == 0, _positionDebtValue >= _vars.debtFloor), "BookKeeper/debt-floor");
        
        // check this only when withdrawing collateral or changing debt
        if (_collateralValue <= 0 || _debtShare != 0) {
            require(_positionDebtValue <= _vars.positionDebtCeiling, "BookKeeper/position-debt-ceiling-exceeded");
        }
        
        collateralToken[_collateralPoolId][_collateralOwner] = sub(collateralToken[_collateralPoolId][_collateralOwner], _collateralValue);
        stablecoin[_stablecoinOwner] = add(stablecoin[_stablecoinOwner], _debtValue);

        positions[_collateralPoolId][_positionAddress] = position;

        emit LogAdjustPosition(
            msg.sender,
            _collateralPoolId,
            _positionAddress,
            position.lockedCollateral,
            position.debtShare,
            _positionDebtValue,
            _collateralValue,
            _debtShare
        );
        emit StablecoinIssuedAmount(
            totalStablecoinIssued,
            _collateralPoolId,
            _poolStablecoinAmount // [rad]
        );
    }

    /// @notice Moves collateral and debt from one position to another in a specific collateral pool.
    /// @dev This function can only be called by an entity with the Position Manager role when the BookKeeper contract is not paused.
    /// @dev It ensures that the caller is allowed to manipulate both source and destination positions and the positions remain safe after the move.
    /// @param _collateralPoolId The ID of the collateral pool where the positions are located.
    /// @param _src The address of the source position from which collateral and debt are being moved.
    /// @param _dst The address of the destination position to which collateral and debt are being moved.
    /// @param _collateralAmount The amount of collateral being moved from the source to the destination position.
    /// @param _debtShare The amount of debt share being moved from the source to the destination position.
    // solhint-enable function-max-lines
    function movePosition(
        bytes32 _collateralPoolId,
        address _src,
        address _dst,
        int256 _collateralAmount,
        int256 _debtShare
    ) external override nonReentrant whenNotPaused onlyPositionManager {
        Position storage _positionSrc = positions[_collateralPoolId][_src];
        Position storage _positionDst = positions[_collateralPoolId][_dst];

        ICollateralPoolConfig.CollateralPoolInfo memory _vars = ICollateralPoolConfig(collateralPoolConfig).getCollateralPoolInfo(_collateralPoolId);

        _positionSrc.lockedCollateral = sub(_positionSrc.lockedCollateral, _collateralAmount);
        _positionSrc.debtShare = sub(_positionSrc.debtShare, _debtShare);
        _positionDst.lockedCollateral = add(_positionDst.lockedCollateral, _collateralAmount);
        _positionDst.debtShare = add(_positionDst.debtShare, _debtShare);

        uint256 _utab = _positionSrc.debtShare * _vars.debtAccumulatedRate;
        uint256 _vtab = _positionDst.debtShare * _vars.debtAccumulatedRate;

        require(both(_wish(_src, msg.sender), _wish(_dst, msg.sender)), "BookKeeper/movePosition/not-allowed");

        require(_utab <= _positionSrc.lockedCollateral * _vars.priceWithSafetyMargin, "BookKeeper/not-safe-src");
        require(_vtab <= _positionDst.lockedCollateral * _vars.priceWithSafetyMargin, "BookKeeper/not-safe-dst");

        require(either(_utab >= _vars.debtFloor, _positionSrc.debtShare == 0), "BookKeeper/debt-floor-src");
        require(either(_vtab >= _vars.debtFloor, _positionDst.debtShare == 0), "BookKeeper/debt-floor-dst");

        require(_vtab <= _vars.positionDebtCeiling, "BookKeeper/position-debt-ceiling-exceeded-dst");
    }

    /// @notice Confiscates a position for liquidation. It seizes collateral and marks a debt.
    /// @dev This function can only be called by an entity with the Liquidation Engine role when the BookKeeper contract is not paused.
    /// @dev The seized collateral will be transferred to the Auctioneer contracts and later moved to the corresponding liquidator addresses.
    /// @dev The stablecoin debt will be initially marked in the SystemDebtEngine contract and will be cleared later on from a successful liquidation.
    /// @dev If the debt is not fully liquidated, the remaining debt will stay inside SystemDebtEngine as bad debt.
    /// @param _collateralPoolId The ID of the collateral pool where the positions are located.
    /// @param _positionAddress The address of the position from which collateral and debt are being confiscated.
    /// @param _collateralCreditor The address where confiscated collateral will be transferred.
    /// @param _stablecoinDebtor The address from which the stablecoin debt is being confiscated.
    /// @param _collateralAmount The amount of collateral being confiscated from the position.
    /// @param _debtShare The amount of debt share being confiscated from the position.
    function confiscatePosition(
        bytes32 _collateralPoolId,
        address _positionAddress,
        address _collateralCreditor,
        address _stablecoinDebtor,
        int256 _collateralAmount,
        int256 _debtShare
    ) external override nonReentrant whenNotPaused onlyLiquidationEngine {
        Position storage position = positions[_collateralPoolId][_positionAddress];
        ICollateralPoolConfig.CollateralPoolInfo memory _vars = ICollateralPoolConfig(collateralPoolConfig).getCollateralPoolInfo(_collateralPoolId);
        // -- col from position
        position.lockedCollateral = add(position.lockedCollateral, _collateralAmount);
        // -- debt from position
        position.debtShare = add(position.debtShare, _debtShare);
        _vars.totalDebtShare = add(_vars.totalDebtShare, _debtShare);
        ICollateralPoolConfig(collateralPoolConfig).setTotalDebtShare(_collateralPoolId, _vars.totalDebtShare);

        int256 _debtValue = mul(_vars.debtAccumulatedRate, _debtShare);

        uint256 _poolStablecoinAmount = poolStablecoinIssued[_collateralPoolId];
        poolStablecoinIssued[_collateralPoolId] = add(_poolStablecoinAmount, _debtValue);
        // ++ col to _collateralCreditor(showStopper in case of skim/accumulateBadDebt)
        collateralToken[_collateralPoolId][_collateralCreditor] = sub(collateralToken[_collateralPoolId][_collateralCreditor], _collateralAmount);
        // ++ debt to systemDebtEngine
        systemBadDebt[_stablecoinDebtor] = sub(systemBadDebt[_stablecoinDebtor], _debtValue);
        totalUnbackedStablecoin = sub(totalUnbackedStablecoin, _debtValue);
    }

    /// @notice Settles the system's bad debt of the caller.
    /// @dev This function can be called by the SystemDebtEngine, which incurs the system debt. The BookKeeper contract must not be paused.
    /// @dev Even though the function has no modifier that restricts access exclusively to SystemDebtEngine,
    ///      the action of the function—reducing the systemBadDebt of msg.sender—effectively limits the function callers to SystemDebtEngine.
    /// @dev To execute this function, the SystemDebtEngine must have enough stablecoin, which typically comes from the protocol's surplus.
    /// @dev A successful execution of this function removes the bad debt from the system.
    /// @param _value The amount of bad debt to be settled.
    ////
    function settleSystemBadDebt(uint256 _value) external override nonReentrant whenNotPaused {
        systemBadDebt[msg.sender] -= _value;
        stablecoin[msg.sender] -= _value;
        totalUnbackedStablecoin -= _value;
        totalStablecoinIssued -= _value;
    }

    /// @notice Mints unbacked stablecoin.
    /// @dev This function can only be called by the Mintable role when the BookKeeper contract is not paused.
    /// @dev It also requires the system to be live.
    /// @param _from The address from which the unbacked stablecoin is being minted.
    /// @param _to The address to which the unbacked stablecoin is being minted.
    /// @param _value The amount of unbacked stablecoin to mint.
    function mintUnbackedStablecoin(address _from, address _to, uint256 _value) external override nonReentrant whenNotPaused onlyMintable {
        require(_value > 0, "bookKeeper/mintUnbackedStablecoin-zero-amount");
        _requireLive();
        require(_from != address(0) && _to != address(0), "BookKeeper/zero-address");
        systemBadDebt[_from] += _value;
        stablecoin[_to] += _value;
        totalUnbackedStablecoin += _value;
        totalStablecoinIssued += _value;
    }

    /// @notice Accrue stability fee for a specific collateral pool.
    /// @dev This function can only be called by the StabilityFeeCollector role when the BookKeeper contract is not paused.
    /// @dev It also requires the system to be live.
    /// @param _collateralPoolId The ID of the collateral pool where the stability fee is being accrued.
    /// @param _stabilityFeeRecipient The address that will receive the accrued stability fee.
    /// @param _debtAccumulatedRate The debt accumulation rate used in the calculation of the stability fee.
    function accrueStabilityFee(
        bytes32 _collateralPoolId,
        address _stabilityFeeRecipient,
        int256 _debtAccumulatedRate
    ) external override nonReentrant whenNotPaused onlyStabilityFeeCollector {
        _requireLive();

        ICollateralPoolConfig.CollateralPoolInfo memory _vars = ICollateralPoolConfig(collateralPoolConfig).getCollateralPoolInfo(_collateralPoolId);

        _vars.debtAccumulatedRate = add(_vars.debtAccumulatedRate, _debtAccumulatedRate);
        ICollateralPoolConfig(collateralPoolConfig).setDebtAccumulatedRate(_collateralPoolId, _vars.debtAccumulatedRate);
        int256 _value = mul(_vars.totalDebtShare, _debtAccumulatedRate); // [rad]

        uint256 _poolStablecoinAmount = poolStablecoinIssued[_collateralPoolId];
        poolStablecoinIssued[_collateralPoolId] = add(_poolStablecoinAmount, _value);

        stablecoin[_stabilityFeeRecipient] = add(stablecoin[_stabilityFeeRecipient], _value);
        totalStablecoinIssued = add(totalStablecoinIssued, _value);
    }

    function _requireLive() internal view {
        require(live == 1, "BookKeeper/not-live");
    }

    function _requireAllowedPositionAdjustment(address _positionAddress, address _usr) internal view {
        require(_wish(_positionAddress, _usr), "BookKeeper/not-allowed-position-adjustment");
    }

    /// @dev Check if the `usr` address is allowed to adjust the position address (`bit`).
    /// @param bit The position address
    /// @param usr The address to be checked for permission
    function _wish(address bit, address usr) internal view returns (bool) {
        return either(bit == usr, positionWhitelist[bit][usr] == 1);
    }
}
