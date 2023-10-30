// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

import "./PositionHandler.sol";
import "../interfaces/IManager.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/IGenericTokenAdapter.sol";
import "../interfaces/IShowStopper.sol";
import "../interfaces/ISetPrice.sol";
import "../interfaces/IPriceFeed.sol";
import "../interfaces/IPriceOracle.sol";

contract PositionManager is PausableUpgradeable, IManager {
    struct List {
        uint256 prev;
        uint256 next;
    }

    address public override bookKeeper;
    address public showStopper;
    address public priceOracle;

    uint256 public lastPositionId;
    /// @dev Mapping of positionId => positionHandler
    mapping(uint256 => address) public override positions;
    /// @dev Mapping of positionId => prev & next positionId; Double linked list
    mapping(uint256 => List) public list;
    /// @dev Mapping of positionId => owner
    mapping(uint256 => address) public override owners;
    /// @dev Mapping of positionHandler => owner
    mapping(address => address) public override mapPositionHandlerToOwner;
    /// @dev Mapping of positionId => collateralPool
    mapping(uint256 => bytes32) public override collateralPools;

    mapping(address => uint256) public ownerFirstPositionId;
    mapping(address => uint256) public ownerLastPositionId;
    mapping(address => uint256) public ownerPositionCount;

    /// @dev Mapping of owner => whitelisted address that can manage owner's position
    mapping(address => mapping(uint256 => mapping(address => uint256))) public override ownerWhitelist;
    /// @dev Mapping of owner => whitelisted address that can migrate position
    mapping(address => mapping(address => uint256)) public migrationWhitelist;

    event LogNewPosition(address indexed _usr, address indexed _own, uint256 indexed _positionId);
    event LogAllowManagePosition(address indexed _caller, uint256 indexed _positionId, address _owner, address _user, uint256 _ok);
    event LogAllowMigratePosition(address indexed _caller, address _user, uint256 _ok);
    event LogExportPosition(uint256 indexed _positionId, address _source, address _destination, uint256 _lockedCollateral, uint256 _debtShare);
    event LogImportPosition(uint256 indexed _positionId, address _source, address _destination, uint256 _lockedCollateral, uint256 _debtShare);
    event LogMovePosition(uint256 _sourceId, uint256 _destinationId, uint256 _lockedCollateral, uint256 _debtShare);

    /// @dev Require that the caller must be position's owner or owner whitelist
    modifier onlyOwnerAllowed(uint256 _positionId) {
        require(msg.sender == owners[_positionId] || ownerWhitelist[owners[_positionId]][_positionId][msg.sender] == 1, "owner not allowed");
        _;
    }

    /// @dev Require that the caller must be allowed to migrate position to the migrant address
    modifier onlyMigrationAllowed(address _migrantAddress) {
        require(msg.sender == _migrantAddress || migrationWhitelist[_migrantAddress][msg.sender] == 1, "migration not allowed");
        _;
    }

    modifier onlyOwnerOrGov() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(IBookKeeper(bookKeeper).accessControlConfig());
        require(
            _accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender) ||
                _accessControlConfig.hasRole(_accessControlConfig.GOV_ROLE(), msg.sender),
            "!(ownerRole or govRole)"
        );
        _;
    }

    function initialize(address _bookKeeper, address _showStopper, address _priceOracle) external initializer {
        PausableUpgradeable.__Pausable_init();

        require(IBookKeeper(_bookKeeper).totalStablecoinIssued() >= 0, "PositionManager/invalid-bookKeeper"); // Sanity Check Call
        bookKeeper = _bookKeeper;

        require(IShowStopper(_showStopper).live() == 1, "PositionManager/showStopper-not-live"); // Sanity Check Call
        showStopper = _showStopper;

        require(IPriceOracle(_priceOracle).stableCoinReferencePrice() >= 0, "PositionManager/invalid-priceOracle"); // Sanity Check Call
        priceOracle = _priceOracle;
    }

    /// @dev Allow/disallow a user to manage the position
    /// @param _positionId The position id
    /// @param _user The address to be allowed for managing the position
    /// @param _ok Ok flag to allow/disallow. 1 for allow and 0 for disallow.
    function allowManagePosition(uint256 _positionId, address _user, uint256 _ok) external override whenNotPaused onlyOwnerAllowed(_positionId) {
        require(_ok < 2, "PositionManager/invalid-ok");
        ownerWhitelist[owners[_positionId]][_positionId][_user] = _ok;
        emit LogAllowManagePosition(msg.sender, _positionId, owners[_positionId], _user, _ok);
    }

    /// @dev Allow/disallow a user to importPosition/exportPosition from/to msg.sender
    /// @param _user The address of user that will be allowed to do such an action to msg.sender
    /// @param _ok Ok flag to allow/disallow
    function allowMigratePosition(address _user, uint256 _ok) external override whenNotPaused {
        require(_ok < 2, "PositionManager/invalid-ok");
        migrationWhitelist[msg.sender][_user] = _ok;
        emit LogAllowMigratePosition(msg.sender, _user, _ok);
    }

    /// @dev Open a new position for a given user address.
    /// @param _collateralPoolId The collateral pool id that will be used for this position
    /// @param _user The user address that is owned this position
    function open(bytes32 _collateralPoolId, address _user) external override whenNotPaused returns (uint256) {
        require(_user != address(0), "PositionManager/user-address(0)");
        uint256 _debtAccumulatedRate = ICollateralPoolConfig(IBookKeeper(bookKeeper).collateralPoolConfig()).getDebtAccumulatedRate(
            _collateralPoolId
        );
        require(_debtAccumulatedRate != 0, "PositionManager/collateralPool-not-init");

        lastPositionId += 1;
        positions[lastPositionId] = address(new PositionHandler(bookKeeper));
        owners[lastPositionId] = _user;
        mapPositionHandlerToOwner[positions[lastPositionId]] = _user;
        collateralPools[lastPositionId] = _collateralPoolId;

        // Add new position to double linked list and pointers
        if (ownerFirstPositionId[_user] == 0) {
            ownerFirstPositionId[_user] = lastPositionId;
        }
        if (ownerLastPositionId[_user] != 0) {
            list[lastPositionId].prev = ownerLastPositionId[_user];
            list[ownerLastPositionId[_user]].next = lastPositionId;
        }
        ownerLastPositionId[_user] = lastPositionId;
        ownerPositionCount[_user] += 1;

        emit LogNewPosition(msg.sender, _user, lastPositionId);

        return lastPositionId;
    }

    /// @dev Give the position ownership to a destination address
    /// @param _positionId The position id to be given away ownership
    /// @param _destination The destination to be a new owner of the position
    function give(uint256 _positionId, address _destination) external override whenNotPaused onlyOwnerAllowed(_positionId) {
        require(_destination != address(0), "destination address(0)");
        require(_destination != owners[_positionId], "destination already owner");

        // Remove transferred position from double linked list of origin user and pointers
        if (list[_positionId].prev != 0) {
            // Set the next pointer of the prev position (if exists) to the next of the transferred one
            list[list[_positionId].prev].next = list[_positionId].next;
        }

        if (list[_positionId].next != 0) {
            // If wasn't the last one set the prev pointer of the next position to the prev of the transferred one
            list[list[_positionId].next].prev = list[_positionId].prev;
        } else {
            // If was the last one update last pointer of the owner
            ownerLastPositionId[owners[_positionId]] = list[_positionId].prev;
        }

        if (ownerFirstPositionId[owners[_positionId]] == _positionId) {
            // If was the first one update first pointer of the owner
            ownerFirstPositionId[owners[_positionId]] = list[_positionId].next;
        }
        ownerPositionCount[owners[_positionId]] -= 1;

        // Transfer ownership
        owners[_positionId] = _destination;
        mapPositionHandlerToOwner[positions[_positionId]] = _destination;

        // Add transferred position to double linked list of destiny user and pointers
        list[_positionId].prev = ownerLastPositionId[_destination];
        list[_positionId].next = 0;
        if (ownerLastPositionId[_destination] != 0) {
            list[ownerLastPositionId[_destination]].next = _positionId;
        }
        if (ownerFirstPositionId[_destination] == 0) {
            ownerFirstPositionId[_destination] = _positionId;
        }
        ownerLastPositionId[_destination] = _positionId;
        ownerPositionCount[_destination] += 1;
    }

    /// @dev Adjust the position keeping the generated stablecoin or collateral freed in the positionHandler address.
    /// @param _positionId The position id to be adjusted
    /// @param _collateralValue The collateralValue to be adjusted
    /// @param _debtShare The debtShare to be adjusted
    function adjustPosition(
        uint256 _positionId,
        int256 _collateralValue,
        int256 _debtShare,
        bytes calldata /* _data */
    ) external override whenNotPaused onlyOwnerAllowed(_positionId) {
        bytes32 _collateralPoolId = collateralPools[_positionId];
        _requireHealthyPrice(_collateralPoolId);

        address _positionAddress = positions[_positionId];
        IBookKeeper(bookKeeper).adjustPosition(
            _collateralPoolId,
            _positionAddress,
            _positionAddress,
            _positionAddress,
            _collateralValue,
            _debtShare
        );
        ISetPrice(priceOracle).setPrice(_collateralPoolId);
    }

    /// @dev Transfer wad amount of position's collateral from the positionHandler address to a destination address.
    /// @param _positionId The position id to move collateral from
    /// @param _destination The destination to received collateral
    /// @param _wad The amount in wad to be moved
    function moveCollateral(
        uint256 _positionId,
        address _destination,
        uint256 _wad,
        bytes calldata /* _data */
    ) external override whenNotPaused onlyOwnerAllowed(_positionId) {
        require(_destination != address(0), "PositionManager/dst-address(0)");
        bytes32 _collateralPoolId = collateralPools[_positionId];
        _requireHealthyPrice(_collateralPoolId);

        IBookKeeper(bookKeeper).moveCollateral(collateralPools[_positionId], positions[_positionId], _destination, _wad);
    }

    /// @dev Transfer wad amount of any type of collateral (collateralPoolId) from the positionHandler address to the destination address
    /// This function has the purpose to take away collateral from the system that doesn't correspond to the position but was sent there wrongly
    /// @param _collateralPoolId The collateral pool id
    /// @param _positionId The position id to move collateral from
    /// @param _destination The destination to recevied collateral
    /// @param _wad The amount in wad to be moved
    function moveCollateral(
        bytes32 _collateralPoolId,
        uint256 _positionId,
        address _destination,
        uint256 _wad,
        bytes calldata /* _data */
    ) external whenNotPaused onlyOwnerAllowed(_positionId) {
        require(_destination != address(0), "PositionManager/dst-address(0)");
        _requireHealthyPrice(_collateralPoolId);
        IBookKeeper(bookKeeper).moveCollateral(_collateralPoolId, positions[_positionId], _destination, _wad);
    }

    /// @dev Transfer rad amount of stablecoin from the positionHandler address to the destination address
    /// @param _positionId The position id to move stablecoin from
    /// @param _destination The destination to received stablecoin
    /// @param _rad The amount in rad to be moved
    function moveStablecoin(uint256 _positionId, address _destination, uint256 _rad) external override whenNotPaused onlyOwnerAllowed(_positionId) {
        require(_destination != address(0), "PositionManager/dst-address(0)");
        IBookKeeper(bookKeeper).moveStablecoin(positions[_positionId], _destination, _rad);
    }

    /// @dev Export the positions's lockedCollateral and debtShare to a different destination address
    /// The destination address must allow position's owner to do so.
    /// @param _positionId The position id to be exported
    /// @param _destination The PositionHandler to be exported to
    function exportPosition(
        uint256 _positionId,
        address _destination
    ) external override whenNotPaused onlyOwnerAllowed(_positionId) onlyMigrationAllowed(_destination) {
        require(_destination != address(0), "PositionManager/dst-address(0)");
        (uint256 _lockedCollateral, uint256 _debtShare) = IBookKeeper(bookKeeper).positions(collateralPools[_positionId], positions[_positionId]);
        IBookKeeper(bookKeeper).movePosition(
            collateralPools[_positionId],
            positions[_positionId],
            _destination,
            int256(_lockedCollateral),
            int256(_debtShare)
        );
        emit LogExportPosition(_positionId, positions[_positionId], _destination, _lockedCollateral, _debtShare);
    }

    /// @dev Import lockedCollateral and debtShare from the source address to
    /// the PositionHandler owned by the PositionManager.
    /// The source address must allow position's owner to do so.
    /// @param _source The source PositionHandler to be moved to this PositionManager
    /// @param _positionId The position id to be moved to this PositionManager
    function importPosition(
        address _source,
        uint256 _positionId
    ) external override whenNotPaused onlyMigrationAllowed(_source) onlyOwnerAllowed(_positionId) {
        (uint256 _lockedCollateral, uint256 _debtShare) = IBookKeeper(bookKeeper).positions(collateralPools[_positionId], _source);
        IBookKeeper(bookKeeper).movePosition(
            collateralPools[_positionId],
            _source,
            positions[_positionId],
            int256(_lockedCollateral),
            int256(_debtShare)
        );
        emit LogImportPosition(_positionId, _source, positions[_positionId], _lockedCollateral, _debtShare);
    }

    /// @dev Move position's lockedCollateral and debtShare
    /// from the source PositionHandler to the destination PositionHandler
    /// @param _sourceId The source PositionHandler
    /// @param _destinationId The destination PositionHandler
    function movePosition(
        uint256 _sourceId,
        uint256 _destinationId
    ) external override whenNotPaused onlyOwnerAllowed(_sourceId) onlyOwnerAllowed(_destinationId) {
        require(collateralPools[_sourceId] == collateralPools[_destinationId], "!same collateral pool");
        (uint256 _lockedCollateral, uint256 _debtShare) = IBookKeeper(bookKeeper).positions(collateralPools[_sourceId], positions[_sourceId]);
        IBookKeeper(bookKeeper).movePosition(
            collateralPools[_sourceId],
            positions[_sourceId],
            positions[_destinationId],
            int256(_lockedCollateral),
            int256(_debtShare)
        );
        emit LogMovePosition(_sourceId, _destinationId, _lockedCollateral, _debtShare);
    }

    /// @dev Redeem locked collateral from a position when emergency shutdown is activated
    /// @param _posId The position id to be adjusted
    /// @param _data The extra data for adapter
    function redeemLockedCollateral(
        uint256 _posId,
        address _collateralReceiver,
        bytes calldata _data
    ) external override whenNotPaused onlyOwnerAllowed(_posId) {
        address _positionAddress = positions[_posId];
        IShowStopper(showStopper).redeemLockedCollateral(
            collateralPools[_posId],
            _positionAddress,
            _collateralReceiver,
            _data
        );
    }

    function setPriceOracle(address _priceOracle) external onlyOwnerOrGov {
        require(IPriceOracle(_priceOracle).stableCoinReferencePrice() >= 0, "PositionManager/invalid-priceOracle"); // Sanity Check Call
        priceOracle = _priceOracle;
    }

    function setBookKeeper(address _bookKeeper) external onlyOwnerOrGov {
        require(IBookKeeper(_bookKeeper).totalStablecoinIssued() >= 0, "PositionManager/invalid-bookKeeper"); // Sanity Check Call
        bookKeeper = _bookKeeper;
    }
    /// @dev access: OWNER_ROLE, GOV_ROLE
    function pause() external onlyOwnerOrGov {
        _pause();
    }
    /// @dev access: OWNER_ROLE, GOV_ROLE
    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    function updatePrice(bytes32 _poolId) external override whenNotPaused {
        ISetPrice(priceOracle).setPrice(_poolId);
    }

    function _requireHealthyPrice(bytes32 _poolId) internal view {
        IPriceFeed _priceFeed = IPriceFeed(ICollateralPoolConfig(IBookKeeper(bookKeeper).collateralPoolConfig()).getPriceFeed(_poolId));
        require(_priceFeed.isPriceOk(), "PositionManager/price-is-not-healthy");
    }
}
