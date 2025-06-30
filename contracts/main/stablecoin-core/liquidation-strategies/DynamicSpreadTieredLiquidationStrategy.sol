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
import "../../interfaces/IAccessControlConfig.sol";
import "../../interfaces/ICollateralPoolConfig.sol";
import "../../utils/SafeToken.sol";
import "../../utils/CommonMath.sol";

/**
 * @title DynamicSpreadTieredLiquidationStrategy (DSTL)
 * @notice Implements the Dynamic Spread + Tiered Partial Liquidation model described in DSTL.md.
 *         This strategy extends the classic fixed spread model by:
 *          1. Dynamic liquidator incentive (liquidation spread) – higher spread when a position is deeper
 *             under-water, lower spread when it is near the threshold.
 *          2. Dynamic close factor – the portion of debt liquidated increases as the position becomes riskier.
 *          3. Tiered partial liquidations – the dynamic close factor naturally results in increasingly larger
 *             liquidations if Health Factor remains < 1 after previous liquidations.
 *          4. Batch processing & flash-lending integration inherited from the existing strategies.
 *
 *         NOTE: Asset bundling (core component #4 in the white-paper) requires substantial architectural
 *         changes (index vaults & composite price feeds) and is **NOT** implemented here. A detailed design
 *         stub is provided at the bottom of this file for future work.
 */
contract DynamicSpreadTieredLiquidationStrategy is CommonMath, PausableUpgradeable, ReentrancyGuardUpgradeable, ILiquidationStrategy {
    using SafeToken for address;

    // ---------------------------------------------------------------------------------------------
    // ░░░░░░░  S T O R A G E
    // ---------------------------------------------------------------------------------------------

    struct LiquidationInfo {
        uint256 debtShareToBeLiquidated; // [wad]
        uint256 debtValueToBeLiquidated; // [rad]
        uint256 collateralAmountToBeLiquidated; // [wad]
        uint256 treasuryFees; // [wad]
    }

    struct Vars {
        uint256 debtAccumulatedRate; // [ray]
        uint256 currentCollateralPrice; // [ray]
        uint256 positionDebtShare; // [wad]
        uint256 positionCollateral; // [wad]
        uint256 positionDebtValue; // [rad]
        uint256 healthFactorBps; // HF in basis pts (== 10_000 is safe line)
        uint256 dynamicCloseFactorBps; // dynamic close factor
        uint256 dynamicIncentiveBps; // dynamic spread
        uint256 debtFloor; // [rad]
        uint256 treasuryFeesBps; // [bps]
    }

    IBookKeeper public bookKeeper; // Core CDP Engine
    ILiquidationEngine public liquidationEngine; // Liquidation module
    ISystemDebtEngine public systemDebtEngine; // Recipient of FXD raised in auctions
    IPriceOracle public priceOracle; // Collateral price module
    IStablecoinAdapter public stablecoinAdapter; // StablecoinAdapter to deposit FXD

    bool public flashLendingEnabled;

    // --- constants ---
    bytes4 internal constant FLASH_LENDING_ID = 0xaf7bd142;
    uint256 internal constant MAX_BPS = 10000; // 100% expressed in basis points
    uint256 public constant SAFE_HF_BPS = 10000; // HF >= 1.0

    // Piecewise-linear tier configuration
    struct TierParams {
        uint256 hfThresholdBps; // exclusive upper bound (must be descending, last must be 0)
        uint256 closeFactorBps; // percentage of debt to liquidate (0-10000)
        uint256 incentiveBps; // liquidation spread (> 10000 means premium)
    }

    TierParams[] public tiers;

    // --- events ---
    event LogDSTLLiquidate(
        bytes32 indexed collateralPoolId,
        address indexed position,
        address indexed liquidator,
        uint256 debtShareLiquidated,
        uint256 debtValueLiquidated,
        uint256 collateralLiquidated,
        uint256 treasuryFees,
        uint256 dynamicCloseFactorBps,
        uint256 dynamicIncentiveBps
    );

    event LogSetTiers(uint256 tierCount);
    event LogSetFlashLendingEnabled(address indexed caller, bool enabled);

    // --- modifiers ---
    modifier onlyOwnerOrGov() {
        IAccessControlConfig acc = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(acc.hasRole(acc.OWNER_ROLE(), msg.sender) || acc.hasRole(acc.GOV_ROLE(), msg.sender), "!(owner|gov)");
        _;
    }

    modifier onlyOwner() {
        IAccessControlConfig acc = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(acc.hasRole(acc.OWNER_ROLE(), msg.sender), "!owner");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    // ---------------------------------------------------------------------------------------------
    // ░░░░░░░  I N I T
    // ---------------------------------------------------------------------------------------------

    function initialize(
        address _bookKeeper,
        address _priceOracle,
        address _liquidationEngine,
        address _systemDebtEngine,
        address _stablecoinAdapter
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        require(_bookKeeper != address(0), "DSTL/invalid-bookKeeper");
        require(_priceOracle != address(0), "DSTL/invalid-oracle");
        require(_liquidationEngine != address(0), "DSTL/invalid-engine");
        require(_systemDebtEngine != address(0), "DSTL/invalid-systemDebtEngine");
        require(_stablecoinAdapter != address(0), "DSTL/invalid-stablecoinAdapter");

        bookKeeper = IBookKeeper(_bookKeeper);
        priceOracle = IPriceOracle(_priceOracle);
        liquidationEngine = ILiquidationEngine(_liquidationEngine);
        systemDebtEngine = ISystemDebtEngine(_systemDebtEngine);
        stablecoinAdapter = IStablecoinAdapter(_stablecoinAdapter);

        // default tiers (can be updated via governance)
        tiers.push(TierParams({hfThresholdBps: 9000, closeFactorBps: 2000, incentiveBps: 10500}));
        tiers.push(TierParams({hfThresholdBps: 8000, closeFactorBps: 5000, incentiveBps: 10800}));
        tiers.push(TierParams({hfThresholdBps: 0, closeFactorBps: 10000, incentiveBps: 11000}));
    }

    // ---------------------------------------------------------------------------------------------
    // ░░░░░░░  A D M I N
    // ---------------------------------------------------------------------------------------------

    function setPriceOracle(address _oracle) external onlyOwner {
        require(IPriceOracle(_oracle).stableCoinReferencePrice() >= 0, "DSTL/invalid-oracle");
        priceOracle = IPriceOracle(_oracle);
    }

    function setBookKeeper(address _bk) external onlyOwner {
        require(_bk != address(0), "DSTL/invalid-bookKeeper");
        bookKeeper = IBookKeeper(_bk);
    }

    function setLiquidationEngine(address _engine) external onlyOwner {
        require(ILiquidationEngine(_engine).live() == 1, "DSTL/engine-not-live");
        liquidationEngine = ILiquidationEngine(_engine);
    }

    function setFlashLendingEnabled(bool _enabled) external onlyOwnerOrGov {
        flashLendingEnabled = _enabled;
        emit LogSetFlashLendingEnabled(msg.sender, _enabled);
    }

    function setTiers(
        uint256[] calldata _hfThresholdBps,
        uint256[] calldata _closeFactorBps,
        uint256[] calldata _incentiveBps
    ) external onlyOwnerOrGov {
        require(
            _hfThresholdBps.length == _closeFactorBps.length && _hfThresholdBps.length == _incentiveBps.length,
            "DSTL/array-length-mismatch"
        );
        delete tiers;
        for (uint256 i = 0; i < _hfThresholdBps.length; i++) {
            if (i > 0) require(_hfThresholdBps[i] < _hfThresholdBps[i - 1], "DSTL/hf-threshold-desc");
            require(_closeFactorBps[i] <= MAX_BPS, "DSTL/cf>100%");
            require(_incentiveBps[i] >= MAX_BPS, "DSTL/incentive<100%");
            tiers.push(TierParams({hfThresholdBps: _hfThresholdBps[i], closeFactorBps: _closeFactorBps[i], incentiveBps: _incentiveBps[i]}));
        }
        require(tiers[tiers.length - 1].hfThresholdBps == 0, "DSTL/last-hf-not-zero");
        emit LogSetTiers(tiers.length);
    }

    // pause/unpause
    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    // ---------------------------------------------------------------------------------------------
    // ░░░░░░░  M A I N   L O G I C
    // ---------------------------------------------------------------------------------------------

    // solhint-disable function-max-lines
    function execute(
        bytes32 _collateralPoolId,
        uint256 _positionDebtShare,
        uint256 _positionCollateralAmount,
        address _positionAddress,
        uint256, // _debtShareToBeLiquidated (ignored – strategy is dynamic)
        uint256 _maxDebtShareToBeLiquidated,
        address _liquidatorAddress,
        address _collateralRecipient,
        bytes calldata _data
    ) external override nonReentrant whenNotPaused {
        IAccessControlConfig acc = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(acc.hasRole(acc.LIQUIDATION_ENGINE_ROLE(), msg.sender), "DSTL/!engine-role");

        require(_positionDebtShare > 0, "DSTL/zero-debt");
        require(_positionCollateralAmount > 0, "DSTL/zero-collateral");
        require(_positionAddress != address(0), "DSTL/zero-position");

        (LiquidationInfo memory info, uint256 dClose, uint256 dInc) = _prepareLiquidation(
            _collateralPoolId,
            _positionDebtShare,
            _positionCollateralAmount,
            _maxDebtShareToBeLiquidated
        );

        _applyLiquidation(
            _collateralPoolId,
            _positionAddress,
            _liquidatorAddress,
            _collateralRecipient,
            _data,
            info
        );

        emit LogDSTLLiquidate(
            _collateralPoolId,
            _positionAddress,
            _liquidatorAddress,
            info.debtShareToBeLiquidated,
            info.debtValueToBeLiquidated,
            info.collateralAmountToBeLiquidated,
            info.treasuryFees,
            dClose,
            dInc
        );
    }
    // solhint-enable function-max-lines

    // --- Internal helper to compute liquidation parameters (avoids stack-too-deep) ---
    function _prepareLiquidation(
        bytes32 _collateralPoolId,
        uint256 _positionDebtShare,
        uint256 _positionCollateralAmount,
        uint256 _maxDebtShareToBeLiquidated
    ) internal returns (LiquidationInfo memory info, uint256 dynamicClose, uint256 dynamicInc) {
        Vars memory v;
        v.positionDebtShare = _positionDebtShare;
        v.positionCollateral = _positionCollateralAmount;
        v.debtAccumulatedRate = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getDebtAccumulatedRate(_collateralPoolId);
        require(v.debtAccumulatedRate > 0, "DSTL/invalid-rate");
        v.currentCollateralPrice = _getFeedPrice(_collateralPoolId);
        require(v.currentCollateralPrice > 0, "DSTL/invalid-price");

        v.positionDebtValue = v.positionDebtShare * v.debtAccumulatedRate;
        uint256 healthFactorRay = rdiv(v.positionCollateral * v.currentCollateralPrice, v.positionDebtValue);
        v.healthFactorBps = healthFactorRay / 1e23;

        (v.dynamicCloseFactorBps, v.dynamicIncentiveBps) = _selectTier(v.healthFactorBps);
        v.debtFloor = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getDebtFloor(_collateralPoolId);
        v.treasuryFeesBps = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getTreasuryFeesBps(_collateralPoolId);

        info.debtShareToBeLiquidated = (v.positionDebtShare * v.dynamicCloseFactorBps) / MAX_BPS;
        if (info.debtShareToBeLiquidated > _maxDebtShareToBeLiquidated) {
            info.debtShareToBeLiquidated = _maxDebtShareToBeLiquidated;
        }
        info.debtValueToBeLiquidated = info.debtShareToBeLiquidated * v.debtAccumulatedRate;

        info.collateralAmountToBeLiquidated = ((info.debtValueToBeLiquidated * v.dynamicIncentiveBps) / MAX_BPS) / v.currentCollateralPrice;

        if (info.collateralAmountToBeLiquidated > v.positionCollateral) {
            info.collateralAmountToBeLiquidated = v.positionCollateral;
            info.debtValueToBeLiquidated = (v.positionCollateral * v.currentCollateralPrice * MAX_BPS) / v.dynamicIncentiveBps;
            info.debtShareToBeLiquidated = info.debtValueToBeLiquidated / v.debtAccumulatedRate;
        }

        if (v.positionDebtValue > info.debtValueToBeLiquidated && v.positionDebtValue - info.debtValueToBeLiquidated < v.debtFloor) {
            info.debtValueToBeLiquidated = v.positionDebtValue;
            info.debtShareToBeLiquidated = v.positionDebtShare;
            info.collateralAmountToBeLiquidated = ((info.debtValueToBeLiquidated * v.dynamicIncentiveBps) / MAX_BPS) / v.currentCollateralPrice;
            if (info.collateralAmountToBeLiquidated > v.positionCollateral) {
                info.collateralAmountToBeLiquidated = v.positionCollateral;
            }
        }

        uint256 incentiveCollateral = info.collateralAmountToBeLiquidated - ((info.collateralAmountToBeLiquidated * MAX_BPS) / v.dynamicIncentiveBps);
        info.treasuryFees = (incentiveCollateral * v.treasuryFeesBps) / MAX_BPS;

        require(info.debtShareToBeLiquidated > 0, "DSTL/nothing-liquidated");
        require(info.collateralAmountToBeLiquidated < 2 ** 255 && info.debtShareToBeLiquidated < 2 ** 255, "DSTL/overflow");

        dynamicClose = v.dynamicCloseFactorBps;
        dynamicInc = v.dynamicIncentiveBps;
    }

    function _applyLiquidation(
        bytes32 _collateralPoolId,
        address _positionAddress,
        address _liquidatorAddress,
        address _collateralRecipient,
        bytes calldata _data,
        LiquidationInfo memory info
    ) private {
        // confiscate
        bookKeeper.confiscatePosition(
            _collateralPoolId,
            _positionAddress,
            address(this),
            address(systemDebtEngine),
            -_toPos(info.collateralAmountToBeLiquidated),
            -_toPos(info.debtShareToBeLiquidated)
        );

        if (info.treasuryFees > 0) {
            bookKeeper.moveCollateral(_collateralPoolId, address(this), address(systemDebtEngine), info.treasuryFees);
        }

        if (
            flashLendingEnabled &&
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
                _liquidatorAddress,
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
            address stablecoin = address(stablecoinAdapter.stablecoin());
            stablecoin.safeTransferFrom(_liquidatorAddress, address(this), ((info.debtValueToBeLiquidated / RAY) + 1));
            stablecoin.safeApprove(address(stablecoinAdapter), ((info.debtValueToBeLiquidated / RAY) + 1));
            stablecoinAdapter.depositRAD(_liquidatorAddress, info.debtValueToBeLiquidated, _collateralPoolId, abi.encode(0));
        }

        bookKeeper.moveStablecoin(_liquidatorAddress, address(systemDebtEngine), info.debtValueToBeLiquidated);
    }

    // ---------------------------------------------------------------------------------------------
    // ░░░░░░░  I N T E R N A L
    // ---------------------------------------------------------------------------------------------

    function _getFeedPrice(bytes32 _collateralPoolId) internal returns (uint256) {
        address priceFeedAddr = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getPriceFeed(_collateralPoolId);
        IPriceFeed pf = IPriceFeed(priceFeedAddr);
        (uint256 p, bool ok) = pf.peekPrice();
        require(ok, "DSTL/bad-price");
        return rdiv(p * BLN, priceOracle.stableCoinReferencePrice());
    }

    function _selectTier(uint256 hfBps) internal view returns (uint256 cf, uint256 inc) {
        for (uint256 i = 0; i < tiers.length; i++) {
            if (hfBps < tiers[i].hfThresholdBps) {
                return (tiers[i].closeFactorBps, tiers[i].incentiveBps);
            }
        }
        return (tiers[tiers.length - 1].closeFactorBps, tiers[tiers.length - 1].incentiveBps);
    }

    function _toPos(uint256 x) internal pure returns (int256) {
        require(int256(x) >= 0, "DSTL/overflow2");
        return int256(x);
    }

    // ---------------------------------------------------------------------------------------------
    // ░░░░░░░  F U T U R E   W O R K   (Asset Bundling placeholder)
    // ---------------------------------------------------------------------------------------------
    /*
     * Asset Bundling (DSTL component #4) requires introducing a new abstraction layer that allows a
     * single liquidation to act upon a basket of collateral types. This necessitates indexed vaults,
     * composite price feeds and potentially ERC-4626 wrappers. Due to its scope the feature will be
     * delivered in a dedicated upgrade and is intentionally **NOT** part of this implementation.
     */
} 