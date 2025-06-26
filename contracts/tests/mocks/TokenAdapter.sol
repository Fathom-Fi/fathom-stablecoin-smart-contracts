// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../../main/interfaces/IBookKeeper.sol";
import "../../main/interfaces/IToken.sol";
import "../../main/interfaces/IGenericTokenAdapter.sol";
import "../../main/interfaces/ICagable.sol";
import "../../main/interfaces/IVault.sol";
import "../../main/utils/SafeToken.sol";

contract TokenAdapter is PausableUpgradeable, ReentrancyGuardUpgradeable, IGenericTokenAdapter, ICagable {
    using SafeToken for address;

    uint256 public live; // Active Flag
    bool public flagVault;

    address public override collateralToken;
    IBookKeeper public bookKeeper; // CDP Engine
    bytes32 public override collateralPoolId; // Collateral Type

    IVault public vault;

    uint256 public override decimals;

    modifier onlyOwner() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(_accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender), "!ownerRole");
        _;
    }

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

    function initialize(address _bookKeeper, bytes32 _collateralPoolId, address _collateralToken) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        live = 1;
        bookKeeper = IBookKeeper(_bookKeeper);
        collateralPoolId = _collateralPoolId;
        collateralToken = _collateralToken;
        decimals = IToken(_collateralToken).decimals();
        require(decimals <= 18, "TokenAdapter/decimals-too-high");
    }

    /// @dev Convert token amount to WAD (18 decimals)
    /// @param _amount Token amount in native decimals
    /// @return WAD amount (18 decimals)
    function _convertToWad(uint256 _amount) internal view returns (uint256) {
        if (decimals == 18) {
            return _amount;
        }
        return _amount * (10 ** (18 - decimals));
    }

    /// @dev Convert WAD amount to token native decimals
    /// @param _wadAmount Amount in WAD (18 decimals)
    /// @return Token amount in native decimals
    function _convertFromWad(uint256 _wadAmount) internal view returns (uint256) {
        if (decimals == 18) {
            return _wadAmount;
        }
        return _wadAmount / (10 ** (18 - decimals));
    }

    /// @dev Cage function halts TokenAdapter contract for good.
    /// Please be cautious with this function since there is no uncage function
    function cage() external override onlyOwnerOrShowStopper {
        if (live == 1) {
            live = 0;
            emit LogCage();
        }
    }

    function deposit(address _usr, uint256 _amount, bytes calldata /* data */) external override nonReentrant whenNotPaused {
        require(_usr != address(0), "TokenAdapter/deposit-address(0)");
        require(live == 1, "TokenAdapter/not-live");
        
        // Check for overflow before conversion
        require(_amount <= uint256(type(int256).max), "TokenAdapter/overflow");
        
        // Convert token amount to WAD for BookKeeper
        uint256 _wadAmount = _convertToWad(_amount);
        require(int256(_wadAmount) > 0, "TokenAdapter/overflow");
        
        bookKeeper.addCollateral(collateralPoolId, _usr, int256(_wadAmount));

        // Move the actual token (in native decimals)
        address(collateralToken).safeTransferFrom(msg.sender, address(this), _amount);
    }

    function withdraw(address _usr, uint256 _amount, bytes calldata /* data */) external override nonReentrant whenNotPaused {
        // Check for overflow before conversion
        require(_amount <= uint256(type(int256).max), "TokenAdapter/overflow");
        
        // Convert token amount to WAD for BookKeeper operations  
        uint256 _wadAmount = _convertToWad(_amount);
        require(int256(_wadAmount) > 0, "TokenAdapter/overflow");
        
        bookKeeper.addCollateral(collateralPoolId, msg.sender, -int256(_wadAmount));

        address(collateralToken).safeTransfer(_usr, _amount);
    }

    function emergencyWithdraw(address _to) external nonReentrant {
        require(_to != address(0), "TokenAdapter/emergency-address(0)");
        if (live == 0) {
            uint256 _wadAmount = bookKeeper.collateralToken(collateralPoolId, msg.sender);
            bookKeeper.addCollateral(collateralPoolId, msg.sender, -int256(_wadAmount));

            // Convert WAD amount back to token native decimals for transfer
            uint256 _tokenAmount = _convertFromWad(_wadAmount);
            address(collateralToken).safeTransfer(_to, _tokenAmount);
        }
    }

    function setVault(address _vault) external {
        require(true != flagVault, "CollateralTokenAdapter/Vault-set-already");
        require(_vault != address(0), "CollateralTokenAdapter/zero-vault");
        address vaultsAdapter = IVault(_vault).collateralAdapter();
        require(vaultsAdapter == address(this), "CollateralTokenAdapter/Adapter-no-match");
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(_accessControlConfig.hasRole(_accessControlConfig.ADAPTER_ROLE(), vaultsAdapter), "vaultsAdapter!Adapter");

        flagVault = true;
        vault = IVault(_vault);
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function pause() external onlyOwnerOrGov {
        _pause();
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function unpause() external onlyOwnerOrGov {
        _unpause();
    }
}
