// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../../../interfaces/IBookKeeper.sol";
import "../../../interfaces/ICollateralAdapter.sol";
import "../../../interfaces/ICagable.sol";
import "../../../interfaces/IProxyRegistry.sol";
import "../../../interfaces/IVault.sol";
import "../../../interfaces/IGenericTokenAdapter.sol";
import "../../../interfaces/IToken.sol";
import "../../../utils/SafeToken.sol";
import "../../../utils/CommonMath.sol";

/// @title CollateralTokenAdapter
/// @dev receives collateral from users and deposit in Vault.
contract CollateralTokenAdapter is CommonMath, IGenericTokenAdapter, ICollateralAdapter, PausableUpgradeable, ReentrancyGuardUpgradeable, ICagable {
    using SafeToken for address;

    uint256 public live;
    bool public flagVault;

    address private _collateralToken;
    IBookKeeper public bookKeeper;
    bytes32 private _collateralPoolId;

    IVault public vault;

    IProxyRegistry public proxyWalletFactory;

    /// @dev decimals of the collateral token
    uint256 private _decimals;

    /// @dev Total CollateralTokens that has been staked in WAD
    uint256 public totalShare;

    // Explicit getter functions to implement both interfaces
    function collateralToken() external view override(IGenericTokenAdapter) returns (address) {
        return _collateralToken;
    }

    function collateralPoolId() external view override(ICollateralAdapter, IGenericTokenAdapter) returns (bytes32) {
        return _collateralPoolId;
    }

    function decimals() external view override(IGenericTokenAdapter) returns (uint256) {
        return _decimals;
    }

    mapping(address => bool) public whiteListed;

    event LogDeposit(uint256 _val);
    event LogWithdraw(uint256 _val);
    event LogAddToWhitelist(address indexed _user);
    event LogRemoveFromWhitelist(address indexed _user);
    event LogEmergencyWithdraw(address indexed _caller, address _to);

    modifier onlyOwner() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(_accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender), "CollateralTokenAdapter/not-authorized");
        _;
    }

    modifier onlyProxyWalletOrWhiteListed() {
        require(IProxyRegistry(proxyWalletFactory).isProxy(msg.sender) || whiteListed[msg.sender], "!ProxyOrWhiteList");
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

    constructor() {
        _disableInitializers();
    }

    function initialize(address _bookKeeperAddress, bytes32 _poolId, address _tokenAddress, address _walletFactory) external initializer {
        // 1. Initialized all dependencies
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        require(_bookKeeperAddress != address(0), "CollateralTokenAdapter/zero-book-keeper");
        require(_poolId != bytes32(0), "CollateralTokenAdapter/zero-collateral-pool-id");
        require(_tokenAddress != address(0), "CollateralTokenAdapter/zero-collateral-token");
        require(_walletFactory != address(0), "CollateralTokenAdapter/zero-proxy-wallet-factory");

        live = 1;

        _collateralPoolId = _poolId;
        _collateralToken = _tokenAddress;
        bookKeeper = IBookKeeper(_bookKeeperAddress);
        proxyWalletFactory = IProxyRegistry(_walletFactory);
        
        _decimals = IToken(_tokenAddress).decimals();
        require(_decimals <= 18, "CollateralTokenAdapter/decimals-too-high");
    }

    /// @dev Convert token amount to WAD (18 decimals)
    /// @param _amount Token amount in native decimals
    /// @return WAD amount (18 decimals)
    function _convertToWad(uint256 _amount) internal view returns (uint256) {
        if (_decimals == 18) {
            return _amount;
        }
        return _amount * (10 ** (18 - _decimals));
    }

    /// @dev Convert WAD amount to token native decimals
    /// @param _wadAmount Amount in WAD (18 decimals)
    /// @return Token amount in native decimals
    function _convertFromWad(uint256 _wadAmount) internal view returns (uint256) {
        if (_decimals == 18) {
            return _wadAmount;
        }
        return _wadAmount / (10 ** (18 - _decimals));
    }

    /// @notice Adds an address to the whitelist, allowing it to interact with the contract
    /// @dev Only the contract owner or a governance address can execute this function. The provided address cannot be the zero address.
    /// @param _toBeWhitelisted The address to be added to the whitelist
    function addToWhitelist(address _toBeWhitelisted) external onlyOwnerOrGov {
        require(_toBeWhitelisted != address(0), "CollateralTokenAdapter/whitelist-invalidAdds");
        whiteListed[_toBeWhitelisted] = true;
        emit LogAddToWhitelist(_toBeWhitelisted);
    }

    /// @notice Removes an address from the whitelist
    /// @dev Only the contract owner or a governance address can execute this function.
    /// @param _toBeRemoved The address to be removed from the whitelist
    function removeFromWhitelist(address _toBeRemoved) external onlyOwnerOrGov {
        require(_toBeRemoved != address(0), "CollateralTokenAdapter/removeFromWL-invalidAdds");
        whiteListed[_toBeRemoved] = false;
        emit LogRemoveFromWhitelist(_toBeRemoved);
    }

    /// @dev The `cage` function permanently halts the `collateralTokenAdapter` contract.
    /// Please exercise caution when using this function as there is no corresponding `uncage` function.
    /// The `cage` function in this contract is unique because it must be called before users can initiate `emergencyWithdraw` in the `collateralTokenAdapter`.
    /// It's a must to invoke this function in the `collateralTokenAdapter` during the final phase of an emergency shutdown.
    function cage() external override nonReentrant onlyOwner {
        if (live == 1) {
            live = 0;
            emit LogCage();
        }
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function pause() external onlyOwnerOrGov {
        _pause();
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    /// @dev The `setVault` function stores the address of the vault contract that holds the collateral.
    /// @param _vault the address of vault smart contract
    function setVault(address _vault) external onlyOwner {
        require(true != flagVault, "CollateralTokenAdapter/Vault-set-already");
        require(_vault != address(0), "CollateralTokenAdapter/zero-vault");
        address vaultsAdapter = IVault(_vault).collateralAdapter();
        require(vaultsAdapter == address(this), "CollateralTokenAdapter/Adapter-no-match");
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(_accessControlConfig.hasRole(_accessControlConfig.ADAPTER_ROLE(), vaultsAdapter), "vaultsAdapter!Adapter");

        flagVault = true;
        vault = IVault(_vault);
    }

    /// @param _positionAddress The address that holding states of the position
    /// @param _amount The collateral amount in token's native decimals to be deposited
    /// @param _data The extra data that may needs to execute the deposit
    function deposit(
        address _positionAddress,
        uint256 _amount,
        bytes calldata _data
    ) external override(ICollateralAdapter, IGenericTokenAdapter) nonReentrant whenNotPaused onlyProxyWalletOrWhiteListed {
        require(_positionAddress != address(0), "CollateralTokenAdapter/deposit-address(0)");
        require(_amount > 0, "CollateralTokenAdapter/zero-amount");
        _deposit(_positionAddress, _amount, _data);
    }

    /// @dev Withdraw collateralToken from Vault
    /// @param _usr The address that holding states of the position
    /// @param _amount The collateral amount in token's native decimals to be withdrawn
    function withdraw(
        address _usr,
        uint256 _amount,
        bytes calldata /* _data */
    ) external override(ICollateralAdapter, IGenericTokenAdapter) nonReentrant whenNotPaused onlyProxyWalletOrWhiteListed {
        require(_amount > 0, "CollateralTokenAdapter/zero-amount");
        _withdraw(_usr, _amount);
    }

    /// @notice Withdraws the collateral from the Vault as the last step for emergency shutdown
    /// @dev for excessCollateral withdraw flow of emergency shutdown, please call this fn via proxyWallet
    /// @dev for flow that deposits FXD and then withdraw collateral, please call this fn from EOA.
    /// @dev EMERGENCY WHEN COLLATERAL TOKEN ADAPTER CAGED ONLY. Withdraw COLLATERAL from VAULT A after redeemStablecoin
    function emergencyWithdraw(address _to) external nonReentrant {
        require(_to != address(0), "CollateralTokenAdapter/emergency-address(0)");
        if (live == 0) {
            uint256 _wadAmount = bookKeeper.collateralToken(_collateralPoolId, msg.sender);
            require(_wadAmount < 2 ** 255, "CollateralTokenAdapter/collateral-overflow");
            
            // Convert WAD amount to token native decimals for withdrawal
            uint256 _tokenAmount = _convertFromWad(_wadAmount);
            
            //deduct totalShare (in WAD)
            totalShare -= _wadAmount;

            //deduct emergency withdrawal amount (in WAD)
            bookKeeper.addCollateral(_collateralPoolId, msg.sender, -int256(_wadAmount));
            //withdraw collateralToken from Vault (native decimals)
            vault.withdraw(_tokenAmount);
            //Transfer collateralToken to msg.sender (native decimals)
            address(_collateralToken).safeTransfer(_to, _tokenAmount);
            emit LogEmergencyWithdraw(msg.sender, _to);
        }
    }

    /// @dev Lock collateral token in the vault
    /// deposit collateral tokens to staking contract, and update BookKeeper
    /// @param _positionAddress The position address to be updated
    /// @param _tokenAmount The amount to be deposited (in token's native decimals)
    function _deposit(address _positionAddress, uint256 _tokenAmount, bytes calldata /* _data */) private {
        require(live == 1, "CollateralTokenAdapter/not-live");
        if (_tokenAmount > 0) {
            // Overflow check for int256 cast below
            require(int256(_tokenAmount) > 0, "CollateralTokenAdapter/amount-overflow");
            
            // Convert token native decimals to WAD for BookKeeper
            uint256 _wadAmount = _convertToWad(_tokenAmount);
            require(int256(_wadAmount) > 0, "CollateralTokenAdapter/wad-overflow");
            
            //transfer collateralToken from proxyWallet to adapter (native decimals)
            address(_collateralToken).safeTransferFrom(msg.sender, address(this), _tokenAmount);
            
            //bookKeeping - pass WAD amount to BookKeeper
            bookKeeper.addCollateral(_collateralPoolId, _positionAddress, int256(_wadAmount));
            totalShare += _wadAmount; // totalShare is in WAD
            
            // safeApprove to Vault (native decimals)
            address(_collateralToken).safeApprove(address(vault), _tokenAmount);
            //deposit collateralToken to Vault (native decimals)
            vault.deposit(_tokenAmount);
            emit LogDeposit(_tokenAmount); // collateralToken (native decimals)
        }
    }

    /// @dev withdraw collateral tokens from staking contract, and update BookKeeper
    /// @param _usr The position address to be updated
    /// @param _tokenAmount The amount to be withdrawn (in token's native decimals)
    function _withdraw(address _usr, uint256 _tokenAmount) private {
        if (_tokenAmount > 0) {
            require(int256(_tokenAmount) > 0, "CollateralTokenAdapter/amount-overflow");
            
            // Convert token native decimals to WAD for BookKeeper operations
            uint256 _wadAmount = _convertToWad(_tokenAmount);
            require(bookKeeper.collateralToken(_collateralPoolId, msg.sender) >= _wadAmount, "CollateralTokenAdapter/insufficient collateral amount");
            
            // Update BookKeeper with WAD amount
            bookKeeper.addCollateral(_collateralPoolId, msg.sender, -int256(_wadAmount));
            totalShare -= _wadAmount; // totalShare is in WAD

            //withdraw collateralToken from Vault (native decimals)
            vault.withdraw(_tokenAmount);
            //Transfer collateralToken to proxyWallet (native decimals)
            address(_collateralToken).safeTransfer(_usr, _tokenAmount);
            emit LogWithdraw(_tokenAmount); // native decimals
        }
    }
}
