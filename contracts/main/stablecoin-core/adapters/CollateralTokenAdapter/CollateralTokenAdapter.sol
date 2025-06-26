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

    address public override collateralToken;
    IBookKeeper public bookKeeper;
    bytes32 public override collateralPoolId;

    IVault public vault;

    IProxyRegistry public proxyWalletFactory;

    /// @dev decimals of the collateral token
    uint256 public override decimals;

    /// @dev Total CollateralTokens that has been staked in WAD
    uint256 public totalShare;

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

    function initialize(address _bookKeeper, bytes32 _collateralPoolId, address _collateralToken, address _proxyWalletFactory) external initializer {
        // 1. Initialized all dependencies
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        require(_bookKeeper != address(0), "CollateralTokenAdapter/zero-book-keeper");
        require(_collateralPoolId != bytes32(0), "CollateralTokenAdapter/zero-collateral-pool-id");
        require(_collateralToken != address(0), "CollateralTokenAdapter/zero-collateral-token");
        require(_proxyWalletFactory != address(0), "CollateralTokenAdapter/zero-proxy-wallet-factory");

        live = 1;

        collateralPoolId = _collateralPoolId;
        collateralToken = _collateralToken;
        bookKeeper = IBookKeeper(_bookKeeper);
        proxyWalletFactory = IProxyRegistry(_proxyWalletFactory);
        
        decimals = IToken(_collateralToken).decimals();
        require(decimals <= 18, "CollateralTokenAdapter/decimals-too-high");
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
    /// @param _amount The collateral token amount that being used as a collateral and to be staked to AnkrStakingPool
    /// @param _data The extra data that may needs to execute the deposit
    function deposit(
        address _positionAddress,
        uint256 _amount,
        bytes calldata _data
    ) external override nonReentrant whenNotPaused onlyProxyWalletOrWhiteListed {
        require(_positionAddress != address(0), "CollateralTokenAdapter/deposit-address(0)");
        _deposit(_positionAddress, _amount, _data);
    }

    /// @dev Withdraw collateralToken from Vault
    /// @param _usr The address that holding states of the position
    /// @param _amount The collateralToken amount in Vault to be returned to proxyWallet and then to user
    function withdraw(
        address _usr,
        uint256 _amount,
        bytes calldata /* _data */
    ) external override nonReentrant whenNotPaused onlyProxyWalletOrWhiteListed {
        _withdraw(_usr, _amount);
    }

    /// @notice Withdraws the collateral from the Vault as the last step for emergency shutdown
    /// @dev for excessCollateral withdraw flow of emergency shutdown, please call this fn via proxyWallet
    /// @dev for flow that deposits FXD and then withdraw collateral, please call this fn from EOA.
    /// @dev EMERGENCY WHEN COLLATERAL TOKEN ADAPTER CAGED ONLY. Withdraw COLLATERAL from VAULT A after redeemStablecoin
    function emergencyWithdraw(address _to) external nonReentrant {
        require(_to != address(0), "CollateralTokenAdapter/emergency-address(0)");
        if (live == 0) {
            uint256 _amount = bookKeeper.collateralToken(collateralPoolId, msg.sender);
            require(_amount < 2 ** 255, "CollateralTokenAdapter/collateral-overflow");
            //deduct totalShare
            totalShare -= _amount;

            //deduct emergency withdrawal amount of FXD
            bookKeeper.addCollateral(collateralPoolId, msg.sender, -int256(_amount));
            //withdraw collateralToken from Vault
            vault.withdraw(_amount);
            //Transfer collateralToken to msg.sender
            address(collateralToken).safeTransfer(_to, _amount);
            emit LogEmergencyWithdraw(msg.sender, _to);
        }
    }

    /// @dev Lock collateral token in the vault
    /// deposit collateral tokens to staking contract, and update BookKeeper
    /// @param _positionAddress The position address to be updated
    /// @param _amount The amount to be deposited
    function _deposit(address _positionAddress, uint256 _amount, bytes calldata /* _data */) private {
        require(live == 1, "CollateralTokenAdapter/not-live");
        if (_amount > 0) {
            // Overflow check for int256(wad) cast below
            // Also enforces a non-zero wad
            require(int256(_amount) > 0, "CollateralTokenAdapter/amount-overflow");
            //transfer collateralToken from proxyWallet to adapter
            address(collateralToken).safeTransferFrom(msg.sender, address(this), _amount);
            //bookKeeping
            bookKeeper.addCollateral(collateralPoolId, _positionAddress, int256(_amount));
            totalShare += _amount;

            // safeApprove to Vault
            address(collateralToken).safeApprove(address(vault), _amount);
            //deposit collateralToken to Vault
            vault.deposit(_amount);
            emit LogDeposit(_amount); // collateralToken
        }
    }

    /// @dev withdraw collateral tokens from staking contract, and update BookKeeper
    /// @param _usr The position address to be updated
    /// @param _amount The amount to be withdrawn
    function _withdraw(address _usr, uint256 _amount) private {
        if (_amount > 0) {
            require(int256(_amount) > 0, "CollateralTokenAdapter/amount-overflow");
            require(bookKeeper.collateralToken(collateralPoolId, msg.sender) >= _amount, "CollateralTokenAdapter/insufficient collateral amount");
            bookKeeper.addCollateral(collateralPoolId, msg.sender, -int256(_amount));
            totalShare -= _amount;

            //withdraw collateralToken from Vault
            vault.withdraw(_amount);
            //Transfer collateralToken to proxyWallet
            collateralToken.safeTransfer(_usr, _amount);
            emit LogWithdraw(_amount);
        }
    }
}
