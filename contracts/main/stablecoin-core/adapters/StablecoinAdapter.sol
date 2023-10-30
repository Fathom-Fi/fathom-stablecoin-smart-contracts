// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../../interfaces/IStablecoin.sol";
import "../../interfaces/IBookKeeper.sol";
import "../../interfaces/IStablecoinAdapter.sol";
import "../../interfaces/ICagable.sol";
import "../../interfaces/IPausable.sol";
import "../../utils/CommonMath.sol";

/**
 * @title Stablecoin Adapter contract
 * @dev Handles deposit and withdrawal of stablecoins, along with emergency shutdown (caging) functionality.
 */

contract StablecoinAdapter is CommonMath, PausableUpgradeable, ReentrancyGuardUpgradeable, IStablecoinAdapter, ICagable, IPausable {
    IBookKeeper public override bookKeeper; // CDP Engine
    IStablecoin public override stablecoin; // Stablecoin Token
    uint256 public live; // Active Flag

    modifier onlyOwnerOrGov() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(
            _accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender) ||
                _accessControlConfig.hasRole(_accessControlConfig.GOV_ROLE(), msg.sender),
            "!(ownerRole or govRole)"
        );
        _;
    }

    modifier onlyOwnerOrShowStopper() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(
            _accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender) ||
                _accessControlConfig.hasRole(_accessControlConfig.SHOW_STOPPER_ROLE(), msg.sender),
            "!(ownerRole or showStopperRole)"
        );
        _;
    }

    modifier onlyLiquidationStrategy(bytes32 _collateralPoolId) {
        ICollateralPoolConfig _collateralPoolConfig = ICollateralPoolConfig(bookKeeper.collateralPoolConfig());
        require(
            msg.sender == _collateralPoolConfig.getStrategy(_collateralPoolId),
            "!(LiquidationStrategy)"
        );
        _;
    }

    function initialize(address _bookKeeper, address _stablecoin) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        require(_bookKeeper != address(0), "StablecoinAdapter/zero-book-keeper");
        require(_stablecoin != address(0), "StablecoinAdapter/zero-stablecoin");

        live = 1;
        bookKeeper = IBookKeeper(_bookKeeper);
        stablecoin = IStablecoin(_stablecoin);
    }

    /// @dev Cage function halts stablecoinAdapter contract for good.
    /// Please be cautious with this function since there is no uncage function
    function cage() external override onlyOwnerOrShowStopper {
        if (live == 1) {
            live = 0;
            emit LogCage();
        }
    }

    /**
     * @notice Deposits stablecoin from msg.sender into the BookKeeper.
     * @param usr Address of the user to credit the deposit to.
     * @param wad Amount to deposit. [wad]
     */
    function deposit(address usr, uint256 wad, bytes calldata /* data */) external override nonReentrant whenNotPaused {
        bookKeeper.moveStablecoin(address(this), usr, wad * RAY);
        stablecoin.burn(msg.sender, wad);
    }
    /**
     * @notice Deposits stablecoin from msg.sender into the BookKeeper in RAD.
     * @param usr Address of the user to credit the deposit to.
     * @param rad Amount to deposit. [rad]
     */
    function depositRAD(address usr, uint256 rad, bytes32 collateralPoolId, bytes calldata /* data */) external override nonReentrant whenNotPaused onlyLiquidationStrategy(collateralPoolId) {
        bookKeeper.moveStablecoin(address(this), usr, rad);
        stablecoin.burn(msg.sender, (rad / RAY) + 1);
    }
    /**
     * @notice Withdraws stablecoin to a specified user.
     * @param usr Address of the user to withdraw stablecoin to.
     * @param wad Amount to withdraw. [wad]
     */
    function withdraw(address usr, uint256 wad, bytes calldata /* data */) external override nonReentrant whenNotPaused {
        require(live == 1, "StablecoinAdapter/not-live");
        bookKeeper.moveStablecoin(msg.sender, address(this), wad * RAY);
        stablecoin.mint(usr, wad);
    }
    /// @dev access: OWNER_ROLE, GOV_ROLE
    function pause() external override onlyOwnerOrGov {
        _pause();
    }
    /// @dev access: OWNER_ROLE, GOV_ROLE
    function unpause() external override onlyOwnerOrGov {
        _unpause();
    }
}
