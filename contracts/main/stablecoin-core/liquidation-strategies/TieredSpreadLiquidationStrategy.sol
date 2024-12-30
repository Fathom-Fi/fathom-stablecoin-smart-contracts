// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../../interfaces/IBookKeeper.sol";
import "../../interfaces/IPriceFeed.sol";
import "../../interfaces/IPriceOracle.sol";
import "../../interfaces/ILiquidationEngine.sol";
import "../../interfaces/ILiquidationStrategy.sol";
import "../../interfaces/ISystemDebtEngine.sol";
import "../../interfaces/IFlashLendingCallee.sol";
import "../../interfaces/IGenericTokenAdapter.sol";
import "../../interfaces/IStablecoinAdapter.sol";
import "../../interfaces/IERC165.sol";
import "../../utils/SafeToken.sol";
import "../../utils/CommonMath.sol";

/**
 * @title TieredSpreadLiquidationStrategy
 * @notice A contract representing a tiered spread liquidation strategy.
 * This strategy is used for liquidating undercollateralized positions in a collateral pool.
 * The strategy calculates the amount of debt and collateral to be liquidated based on current market conditions.
 * @dev The TieredSpreadLiquidationStrategy contract implements the ILiquidationStrategy interface.
 */
contract TieredSpreadLiquidationStrategy is CommonMath, PausableUpgradeable, ReentrancyGuardUpgradeable, ILiquidationStrategy {
    using SafeToken for address;

    struct LiquidationInfo {
        uint256 positionDebtShare; // [wad]
        uint256 positionCollateralAmount; // [wad]
        uint256 debtShareToBeLiquidated; // [wad]
        uint256 maxDebtShareToBeLiquidated; // [wad]
        uint256 debtValueToBeLiquidated; // [rad]
        uint256 collateralAmountToBeLiquidated; // [wad]
        uint256 treasuryFees; // [wad]
    }

    struct LocalVars {
        uint256 debtAccumulatedRate; // [ray]
        uint256 closeFactorBps;
        uint256 liquidatorIncentiveBps;
        uint256 debtFloor; // [rad]
        uint256 treasuryFeesBps;
    }

    IBookKeeper public bookKeeper; // Core CDP Engine
    ILiquidationEngine public liquidationEngine; // Liquidation module
    ISystemDebtEngine public systemDebtEngine; // Recipient of FXD raised in auctions
    IPriceOracle public priceOracle; // Collateral price module
    IStablecoinAdapter public stablecoinAdapter; //StablecoinAdapter to deposit FXD to bookKeeper

    bool public flashLendingEnabled;

    bytes4 internal constant FLASH_LENDING_ID = 0xaf7bd142;

    event LogTieredSpreadLiquidate(
        bytes32 indexed _collateralPoolId,
        uint256 _positionDebtShare,
        uint256 _positionCollateralAmount,
        address indexed _positionAddress,
        uint256 _maxDebtShareToBeLiquidated,
        address indexed _liquidatorAddress,
        address _collateralRecipient,
        uint256 _debtShareToBeLiquidated,
        uint256 _debtValueToBeLiquidated,
        uint256 _collateralAmountToBeLiquidated,
        uint256 _treasuryFees
    );
    event LogSetFlashLendingEnabled(address indexed _caller, bool _flashLendingEnabled);
    event LogSetBookKeeper(address _newAddress);

    modifier onlyOwnerOrGov() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(
            _accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender) ||
                _accessControlConfig.hasRole(_accessControlConfig.GOV_ROLE(), msg.sender),
            "!(ownerRole or govRole)"
        );
        _;
    }

    modifier onlyOwner() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(_accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender), "!ownerRole");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the TieredSpreadLiquidationStrategy contract with required dependencies.
    /// @param _bookKeeper The address of the BookKeeper contract.
    /// @param _priceOracle The address of the PriceOracle contract.
    /// @param _liquidationEngine The address of the LiquidationEngine contract.
    /// @param _systemDebtEngine The address of the SystemDebtEngine contract.
    /// @param _stablecoinAdapter The address of the StablecoinAdapter contract used for depositing FXD to the BookKeeper.
    /// @dev Reverts if any of the input parameters are the zero address or invalid.
    function initialize(
        address _bookKeeper,
        address _priceOracle,
        address _liquidationEngine,
        address _systemDebtEngine,
        address _stablecoinAdapter
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        bookKeeper = IBookKeeper(_bookKeeper);

        require(IPriceOracle(_priceOracle).stableCoinReferencePrice() >= 0, "TieredSpreadLiquidationStrategy/invalid-priceOracle"); // Sanity Check Call
        priceOracle = IPriceOracle(_priceOracle);

        require(ILiquidationEngine(_liquidationEngine).live() == 1, "TieredSpreadLiquidationStrategy/liquidationEngine-not-live"); // Sanity Check Call
        liquidationEngine = ILiquidationEngine(_liquidationEngine);

        require(ISystemDebtEngine(_systemDebtEngine).surplusBuffer() >= 0, "TieredSpreadLiquidationStrategy/invalid-systemDebtEngine"); // Sanity Check Call
        systemDebtEngine = ISystemDebtEngine(_systemDebtEngine);

        require(
            address(IStablecoinAdapter(_stablecoinAdapter).stablecoin()) != address(0),
            "TieredSpreadLiquidationStrategy/invalid-stablecoinAdapter"
        ); // Sanity Check Call
        stablecoinAdapter = IStablecoinAdapter(_stablecoinAdapter); //StablecoinAdapter to deposit FXD to bookKeeper
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function pause() external onlyOwnerOrGov {
        _pause();
    }

    /// @dev access: OWNER_ROLE, GOV_ROLE
    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    /// @notice Sets the flash lending feature to enabled or disabled.
    /// @param _flashLendingEnabled The value indicating whether flash lending should be enabled (true) or disabled (false).
    /// @dev This function can only be called by the contract owner or governance.
    /// @dev Emits a LogSetFlashLendingEnabled event upon a successful update.
    function setFlashLendingEnabled(bool _flashLendingEnabled) external onlyOwnerOrGov {
        flashLendingEnabled = _flashLendingEnabled;
        emit LogSetFlashLendingEnabled(msg.sender, _flashLendingEnabled);
    }

    // solhint-disable function-max-lines
    function execute(
        bytes32 _collateralPoolId,
        uint256 _positionDebtShare, // Debt share in a position                         [wad]
        uint256 _positionCollateralAmount, // Collateral Amount in a position           [wad]
        address _positionAddress, // Address that will receive any leftover collateral after liquidation
        uint256,
        uint256 _maxDebtShareToBeLiquidated, // The maximum value of debt to be liquidated as specified by the liquidator in case of full liquidation for slippage control [wad]
        address _liquidatorAddress,
        address _collateralRecipient,
        bytes calldata _data // Data to pass in external call; if length 0, no call is done
    ) external override nonReentrant whenNotPaused {
        require(
            IAccessControlConfig(bookKeeper.accessControlConfig()).hasRole(
                IAccessControlConfig(bookKeeper.accessControlConfig()).LIQUIDATION_ENGINE_ROLE(),
                msg.sender
            ),
            "!liquidationEngineRole"
        );

        _validateValues(_collateralPoolId, _positionDebtShare, _positionCollateralAmount, _positionAddress);

        LiquidationInfo memory info = _calculateLiquidationInfo(
            _collateralPoolId,
            getFeedPrice(_collateralPoolId),
            _positionCollateralAmount,
            _positionDebtShare
        );

        require(
            info.debtShareToBeLiquidated <= _maxDebtShareToBeLiquidated,
            "TieredSpreadLiquidationStrategy/exceed-max-debt-value-to-be-liquidated"
        );
        require(
            info.collateralAmountToBeLiquidated < 2 ** 255 && info.debtShareToBeLiquidated < 2 ** 255,
            "TieredSpreadLiquidationStrategy/overflow"
        );

        bookKeeper.confiscatePosition(
            _collateralPoolId,
            _positionAddress,
            address(this),
            address(systemDebtEngine),
            -_safeToInt256(info.collateralAmountToBeLiquidated),
            -_safeToInt256(info.debtShareToBeLiquidated)
        );
        if (info.treasuryFees > 0) {
            bookKeeper.moveCollateral(_collateralPoolId, address(this), address(systemDebtEngine), info.treasuryFees);
        }
        if (
            flashLendingEnabled == true &&
            _data.length > 0 &&
            _collateralRecipient != address(bookKeeper) &&
            _collateralRecipient != address(liquidationEngine) &&
            IERC165(_collateralRecipient).supportsInterface(FLASH_LENDING_ID)
        ) {
            bookKeeper.moveCollateral(
                _collateralPoolId,
                address(this),
                _collateralRecipient,
                info.collateralAmountToBeLiquidated - info.treasuryFees
            );
            IFlashLendingCallee(_collateralRecipient).flashLendingCall(
                msg.sender,
                info.debtValueToBeLiquidated,
                info.collateralAmountToBeLiquidated - info.treasuryFees,
                _data
            );
        } else {
            IGenericTokenAdapter(ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getAdapter(_collateralPoolId)).withdraw(
                _collateralRecipient,
                info.collateralAmountToBeLiquidated - info.treasuryFees,
                abi.encode(0)
            );
            address _stablecoin = address(stablecoinAdapter.stablecoin());
            _stablecoin.safeTransferFrom(_liquidatorAddress, address(this), ((info.debtValueToBeLiquidated / RAY) + 1));
            _stablecoin.safeApprove(address(stablecoinAdapter), ((info.debtValueToBeLiquidated / RAY) + 1));
            stablecoinAdapter.depositRAD(_liquidatorAddress, info.debtValueToBeLiquidated, _collateralPoolId, abi.encode(0));
        }
        bookKeeper.moveStablecoin(_liquidatorAddress, address(systemDebtEngine), info.debtValueToBeLiquidated);

        info.positionDebtShare = _positionDebtShare;
        info.positionCollateralAmount = _positionCollateralAmount;
        info.maxDebtShareToBeLiquidated = _maxDebtShareToBeLiquidated;
        emit LogTieredSpreadLiquidate(
            _collateralPoolId,
            info.positionDebtShare,
            info.positionCollateralAmount,
            _positionAddress,
            info.maxDebtShareToBeLiquidated,
            _liquidatorAddress,
            _collateralRecipient,
            info.debtShareToBeLiquidated,
            info.debtValueToBeLiquidated,
            info.collateralAmountToBeLiquidated,
            info.treasuryFees
        );
    }

    // solhint-enable function-max-lines

    function setPriceOracle(address _priceOracle) external onlyOwner {
        require(IPriceOracle(_priceOracle).stableCoinReferencePrice() >= 0, "TieredSpreadLiquidationStrategy/invalid-priceOracle"); // Sanity Check Call
        priceOracle = IPriceOracle(_priceOracle);
    }

    function setBookKeeper(address _bookKeeper) external onlyOwner {
        bookKeeper = IBookKeeper(_bookKeeper);
        emit LogSetBookKeeper(_bookKeeper);
    }

    function setLiquidationEngine(address _liquidationEngine) external onlyOwner {
        require(ILiquidationEngine(_liquidationEngine).live() == 1, "TieredSpreadLiquidationStrategy/liquidationEngine-not-live"); // Sanity Check Call
        liquidationEngine = ILiquidationEngine(_liquidationEngine);
    }

    function getFeedPrice(bytes32 _collateralPoolId) internal returns (uint256 feedPrice) {
        address _priceFeedAddress = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getPriceFeed(_collateralPoolId);
        IPriceFeed _priceFeed = IPriceFeed(_priceFeedAddress);
        (uint256 price, bool priceOk) = _priceFeed.peekPrice();
        require(priceOk, "TieredSpreadLiquidationStrategy/invalid-price");
        // (price [wad] * BLN [10 ** 9] ) [ray] / priceOracle.stableCoinReferencePrice [ray]
        feedPrice = rdiv(price * BLN, priceOracle.stableCoinReferencePrice()); // [ray]
    }

    function _validateValues(
        bytes32 _collateralPoolId,
        uint256 _positionDebtShare,
        uint256 _positionCollateralAmount,
        address _positionAddress
    ) internal {
        require(_positionDebtShare > 0, "TieredSpreadLiquidationStrategy/zero-debt");
        require(_positionCollateralAmount > 0, "TieredSpreadLiquidationStrategy/zero-collateral-amount");
        require(_positionAddress != address(0), "TieredSpreadLiquidationStrategy/zero-position-address");
        require(getFeedPrice(_collateralPoolId) > 0, "TieredSpreadLiquidationStrategy/zero-collateral-price");
    }

    // solhint-disable function-max-lines
    function _calculateLiquidationInfo(
        bytes32 _collateralPoolId,
        uint256 _currentCollateralPrice,
        uint256 _positionCollateralAmount,
        uint256 _positionDebtShare
    ) internal view returns (LiquidationInfo memory info) {
        LocalVars memory _vars;
        _vars.debtAccumulatedRate = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getDebtAccumulatedRate(_collateralPoolId); // [ray]
        _vars.closeFactorBps = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getCloseFactorBps(_collateralPoolId);
        _vars.liquidatorIncentiveBps = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getLiquidatorIncentiveBps(_collateralPoolId);
        _vars.debtFloor = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getDebtFloor(_collateralPoolId); // [rad]
        _vars.treasuryFeesBps = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getTreasuryFeesBps(_collateralPoolId);

        uint256 _positionDebtValue = _positionDebtShare * _vars.debtAccumulatedRate;

        require(_vars.closeFactorBps > 0, "TieredSpreadLiquidationStrategy/close-factor-bps-not-set");
        info.debtShareToBeLiquidated = (_positionDebtShare * _vars.closeFactorBps) / 10000; // [wad]
        info.debtValueToBeLiquidated = info.debtShareToBeLiquidated * _vars.debtAccumulatedRate; // [rad]

        uint256 _collateralAmountToBeLiquidated = ((info.debtValueToBeLiquidated * _vars.liquidatorIncentiveBps) / 10000) /
            _currentCollateralPrice; // [wad]

        if (
            _collateralAmountToBeLiquidated > _positionCollateralAmount ||
            (_positionCollateralAmount - _collateralAmountToBeLiquidated) * _currentCollateralPrice <
            _positionDebtValue - info.debtValueToBeLiquidated
        ) {
            info.collateralAmountToBeLiquidated = _positionCollateralAmount;
            info.debtValueToBeLiquidated = (_currentCollateralPrice * _positionCollateralAmount * 10000) / _vars.liquidatorIncentiveBps; // [rad]
        } else {
            if (
                _positionDebtValue > info.debtValueToBeLiquidated && _positionDebtValue - info.debtValueToBeLiquidated < _vars.debtFloor
            ) {
                info.debtValueToBeLiquidated = _positionDebtValue; // [rad]
                info.collateralAmountToBeLiquidated =
                    ((info.debtValueToBeLiquidated * _vars.liquidatorIncentiveBps) / 10000) /
                    _currentCollateralPrice; // [wad]
            } else {
                info.collateralAmountToBeLiquidated = _collateralAmountToBeLiquidated; // [wad]
            }
        }

        info.debtShareToBeLiquidated = info.debtValueToBeLiquidated / _vars.debtAccumulatedRate; // [wad]

        // collateralAmountToBeLiquidated - (collateralAmountToBeLiquidated * 10000 / liquidatorIncentiveBps)
        // 1 - (1 * 10000 / 10500) = 0.047619048 which is roughly around 0.05
        uint256 liquidatorIncentiveCollectedFromPosition = info.collateralAmountToBeLiquidated -
            ((info.collateralAmountToBeLiquidated * 10000) / _vars.liquidatorIncentiveBps); // [wad]

        // liquidatorIncentiveCollectedFromPosition * (treasuryFeesBps) / 10000
        // 0.047619048 * 5000 / 10000
        info.treasuryFees = (liquidatorIncentiveCollectedFromPosition * _vars.treasuryFeesBps) / 10000; // [wad]
    }

    function _safeToInt256(uint256 _number) internal pure returns (int256) {
        require(int256(_number) >= 0, "TieredSpreadLiquidationStrategy/overflow");
        return int256(_number);
    }
    // solhint-enable function-max-lines
}
