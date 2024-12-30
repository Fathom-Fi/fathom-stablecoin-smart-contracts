// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import "../interfaces/IBookKeeper.sol";
import "../interfaces/IShowStopper.sol";
import "../interfaces/ILiquidationEngine.sol";
import "../interfaces/IPriceFeed.sol";
import "../interfaces/IPriceOracle.sol";
import "../interfaces/ISystemDebtEngine.sol";
import "../interfaces/ICagable.sol";
import "../utils/CommonMath.sol";

/**
 * @title ShowStopper Contract
 * @dev The ShowStopper contract is a system component that handles the emergency shutdown process.
 * It allows the system owner to initiate an emergency shutdown, pause certain system functions,
 * calculate and settle bad debt, and finalize the total debt of the system after the shutdown.
 * It also calculates the redeemStablecoin price of each collateral pool and allows users to redeem their stablecoins for collateral tokens.
 */
contract ShowStopper is CommonMath, IShowStopper, Initializable {
    IBookKeeper public bookKeeper; // CDP Engine
    ILiquidationEngine public liquidationEngine;
    ISystemDebtEngine public systemDebtEngine; // Debt Engine
    IPriceOracle public priceOracle;

    uint256 public override live; // Active Flag
    uint256 public cagedTimestamp; // Time of cage                   [unix epoch time]
    uint256 public cageCoolDown; // Processing Cooldown Length             [seconds]
    uint256 public debt; // Total outstanding stablecoin following processing [rad]

    mapping(bytes32 => uint256) public cagePrice; // Cage price              [ray]
    mapping(bytes32 => uint256) public badDebtAccumulator; // Collateral badDebtAccumulator    [wad]
    mapping(bytes32 => uint256) public totalDebtShare; // Total debt per collateralPoolId      [wad]
    mapping(bytes32 => uint256) public finalCashPrice; // Final redeemStablecoin price        [ray]

    mapping(address => uint256) public stablecoinAccumulator; //    [wad]
    mapping(bytes32 => mapping(address => uint256)) public redeemedStablecoinAmount; //    [wad]

    event LogCage(uint256 _cageCoolDown);
    event LogCageCollateralPool(bytes32 indexed _collateralPoolId);

    event LogAccumulateBadDebt(bytes32 indexed _collateralPoolId, address indexed _positionAddress, uint256 _amount, uint256 _debtShare);
    event LogRedeemLockedCollateral(bytes32 indexed _collateralPoolId, address indexed _positionAddress, uint256 _lockedCollateral);
    event LogFinalizeDebt();
    event LogFinalizeCashPrice(bytes32 indexed _collateralPoolId);
    event LogAccumulateStablecoin(address indexed _ownerAddress, uint256 _amount);
    event LogRedeemStablecoin(bytes32 indexed _collateralPoolId, address indexed _ownerAddress, uint256 _amount);

    event LogSetBookKeeper(address indexed _caller, address _bookKeeper);
    event LogSetLiquidationEngine(address indexed _caller, address _liquidationEngine);
    event LogSetSystemDebtEngine(address indexed _caller, address _systemDebtEngine);
    event LogSetPriceOracle(address indexed _caller, address _priceOracle);
    event LogSetCageCoolDown(address indexed _caller, uint256 _cageCoolDown);

    modifier onlyOwner() {
        IAccessControlConfig _accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        require(_accessControlConfig.hasRole(_accessControlConfig.OWNER_ROLE(), msg.sender), "!ownerRole");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _bookKeeper) external initializer {
        bookKeeper = IBookKeeper(_bookKeeper);
        live = 1;
    }

    function setBookKeeper(address _bookKeeper) external onlyOwner {
        require(live == 1, "ShowStopper/not-live");
        bookKeeper = IBookKeeper(_bookKeeper);
        emit LogSetBookKeeper(msg.sender, _bookKeeper);
    }

    function setLiquidationEngine(address _liquidationEngine) external onlyOwner {
        require(live == 1, "ShowStopper/not-live");
        require(_liquidationEngine != address(0), "ShowStopper/zero-liquidation-engine");

        liquidationEngine = ILiquidationEngine(_liquidationEngine);
        emit LogSetLiquidationEngine(msg.sender, _liquidationEngine);
    }

    function setSystemDebtEngine(address _systemDebtEngine) external onlyOwner {
        require(live == 1, "ShowStopper/not-live");
        require(_systemDebtEngine != address(0), "ShowStopper/zero-debt-engine");

        systemDebtEngine = ISystemDebtEngine(_systemDebtEngine);
        emit LogSetSystemDebtEngine(msg.sender, _systemDebtEngine);
    }

    function setPriceOracle(address _priceOracle) external onlyOwner {
        require(live == 1, "ShowStopper/not-live");
        require(_priceOracle != address(0), "ShowStopper/zero-price-oracle");

        priceOracle = IPriceOracle(_priceOracle);
        emit LogSetPriceOracle(msg.sender, _priceOracle);
    }

    /// @notice Initiates the process of emergency shutdown (cage).
    /// @dev This function can only be called by the contract owner.
    /// @param _cageCoolDown Length of the cooldown period for the emergency shutdown, in seconds.
    ///
    /// The cage function starts the emergency shutdown process, which includes the following steps:
    ///  - Start a cooldown period for the emergency shutdown.
    ///  - Pause BookKeeper: locking/unlocking collateral and mint/repay Fathom Stablecoin will not be allowed for any positions.
    ///  - Pause LiquidationEngine: positions will not be liquidated.
    ///  - Pause SystemDebtEngine: no accrual of new debt, no system debt settlement.
    ///  - Pause PriceOracle: no new price updates, no liquidation trigger.
    ///  - Pause all additional components specified in the calldata.
    function cage(
        uint256 _cageCoolDown,
        address[] calldata _additionalComponents
    ) external onlyOwner {
        require(live == 1, "ShowStopper/not-live");
        require(_cageCoolDown >= 1 weeks && _cageCoolDown <= 13 weeks, "ShowStopper/invalid-cool-down");

        live = 0;
        cageCoolDown = _cageCoolDown;
        cagedTimestamp = block.timestamp;
        ICagable(address(bookKeeper)).cage();
        ICagable(address(liquidationEngine)).cage();
        ICagable(address(systemDebtEngine)).cage();
        ICagable(address(priceOracle)).cage();

        for (uint256 i = 0; i < _additionalComponents.length; i++) {
            ICagable(_additionalComponents[i]).cage();
        }

        emit LogCage(_cageCoolDown);
    }

    /// @notice Sets the cage price of a specific collateral pool using the latest price from the PriceOracle.
    /// @dev This function can only be called by the contract owner after the system has been caged (emergency shutdown initiated).
    /// @param _collateralPoolId The ID of the collateral pool to set the cage price for.
    function cagePool(bytes32 _collateralPoolId) external onlyOwner {
        require(live == 0, "ShowStopper/still-live");
        require(cagePrice[_collateralPoolId] == 0, "ShowStopper/cage-price-collateral-pool-id-already-defined");

        uint256 _totalDebtShare = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getTotalDebtShare(_collateralPoolId);
        address _priceFeedAddress = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getPriceFeed(_collateralPoolId);
        IPriceFeed _priceFeed = IPriceFeed(_priceFeedAddress);
        totalDebtShare[_collateralPoolId] = _totalDebtShare;
        require(_priceFeed.isPriceOk() == true, "ShowStopper/price-not-ok");
        cagePrice[_collateralPoolId] = wdiv(priceOracle.stableCoinReferencePrice(), _priceFeed.readPrice());
        emit LogCageCollateralPool(_collateralPoolId);
    }

    /// @notice Inspects a specified position and calculates the current badDebtAccumulator for the collateral pool it belongs to.
    /// @dev The badDebtAccumulator will be used to determine the stablecoin redemption price and ensure all bad debt is covered.
    /// @param _collateralPoolId The ID of the collateral pool that the position belongs to.
    /// @param _positionAddress The address of the position to inspect for bad debt.
    function accumulateBadDebt(bytes32 _collateralPoolId, address _positionAddress) external {
        require(cagePrice[_collateralPoolId] != 0, "ShowStopper/cage-price-collateral-pool-id-not-defined");
        uint256 _debtAccumulatedRate = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getDebtAccumulatedRate(_collateralPoolId); // [ray]
        (uint256 _lockedCollateralAmount, uint256 _debtShare) = bookKeeper.positions(_collateralPoolId, _positionAddress);
        uint256 _debtAmount = rmul(rmul(_debtShare, _debtAccumulatedRate), cagePrice[_collateralPoolId]); // find the amount of debt in the unit of collateralToken
        uint256 _amount = min(_lockedCollateralAmount, _debtAmount); // if debt > lockedCollateralAmount, that's mean bad debt occur
        badDebtAccumulator[_collateralPoolId] = badDebtAccumulator[_collateralPoolId] + _debtAmount - _amount; // accumulate bad debt in badDebtAccumulator (if there is any)

        require(_amount < 2 ** 255 && _debtShare < 2 ** 255, "ShowStopper/overflow");

        bookKeeper.confiscatePosition(
            _collateralPoolId,
            _positionAddress,
            address(this),
            address(systemDebtEngine),
            -_safeToInt256(_amount),
            -_safeToInt256(_debtShare)
        );
        emit LogAccumulateBadDebt(_collateralPoolId, _positionAddress, _amount, _debtShare);
    }

    /// @notice Finalizes the total debt of the system after the emergency shutdown.
    /// @dev This function should be called after all positions have undergone `accumulateBadDebt` or `snip` to settle all debt,
    /// system surplus must be zero, and the emergency shutdown cooldown period has passed.
    /// The total debt will be equivalent to the total stablecoin issued, reflecting the correct value after the emergency shutdown.
    function finalizeDebt() external {
        require(live == 0, "ShowStopper/still-live");
        require(debt == 0, "ShowStopper/debt-not-zero");
        require(bookKeeper.stablecoin(address(systemDebtEngine)) == 0, "ShowStopper/surplus-not-zero");
        require(block.timestamp >= cagedTimestamp + cageCoolDown, "ShowStopper/cage-cool-down-not-finished");
        debt = bookKeeper.totalStablecoinIssued();
        emit LogFinalizeDebt();
    }

    /// @notice Calculates the redeemStablecoin price of a specific collateral pool.
    /// @dev The redeemStablecoin price is the price at which Fathom Stablecoin holders can redeem their stablecoins for collateral tokens.
    /// The price takes into account the deficit/surplus of the collateral pool and ensures all bad debt is covered.
    /// @param _collateralPoolId The ID of the collateral pool to calculate the redeemStablecoin price for.
    function finalizeCashPrice(bytes32 _collateralPoolId) external {
        require(debt != 0, "ShowStopper/debt-zero");
        require(finalCashPrice[_collateralPoolId] == 0, "ShowStopper/final-cash-price-collateral-pool-id-already-defined");

        uint256 _debtAccumulatedRate = ICollateralPoolConfig(bookKeeper.collateralPoolConfig()).getDebtAccumulatedRate(_collateralPoolId); // [ray]
        uint256 _wad = rmul(rmul(totalDebtShare[_collateralPoolId], _debtAccumulatedRate), cagePrice[_collateralPoolId]);

        finalCashPrice[_collateralPoolId] = ((_wad - badDebtAccumulator[_collateralPoolId]) * RAY) / (debt / RAY);

        emit LogFinalizeCashPrice(_collateralPoolId);
    }

    /// @notice Accumulates the deposited stablecoin of the caller into a stablecoinAccumulator to be redeemed into collateral tokens later.
    /// @dev The caller's stablecoin will be locked until they redeem the stablecoins for collateral tokens.
    /// @param _amount The amount of stablecoin to accumulate.
    function accumulateStablecoin(uint256 _amount) external {
        require(_amount != 0, "ShowStopper/amount-zero");
        require(debt != 0, "ShowStopper/debt-zero");
        bookKeeper.moveStablecoin(msg.sender, address(systemDebtEngine), _amount * RAY);
        stablecoinAccumulator[msg.sender] += _amount;
        emit LogAccumulateStablecoin(msg.sender, _amount);
    }

    /// @notice Redeems stablecoin from the stablecoinAccumulator for collateral tokens of a specific collateral pool.
    /// @dev The stablecoin will be redeemed at the corresponding finalCashPrice of the collateral pool.
    /// @param _collateralPoolId The ID of the collateral pool to redeem stablecoin from.
    /// @param _amount The amount of stablecoin to redeem.
    function redeemStablecoin(bytes32 _collateralPoolId, uint256 _amount) external {
        require(_amount != 0, "ShowStopper/amount-zero");
        require(finalCashPrice[_collateralPoolId] != 0, "ShowStopper/final-cash-price-collateral-pool-id-not-defined");
        bookKeeper.moveCollateral(_collateralPoolId, address(this), msg.sender, rmul(_amount, finalCashPrice[_collateralPoolId]));
        redeemedStablecoinAmount[_collateralPoolId][msg.sender] += _amount;
        require(
            redeemedStablecoinAmount[_collateralPoolId][msg.sender] <= stablecoinAccumulator[msg.sender],
            "ShowStopper/insufficient-stablecoin-accumulator-balance"
        );
        emit LogRedeemStablecoin(_collateralPoolId, msg.sender, _amount);
    }

    /// @notice Redeems locked collateral from a position that has been safely settled after the emergency shutdown.
    /// @dev The position must have no debt and should have gone through the `accumulateBadDebt` or `smip` process already.
    /// @param _collateralPoolId The ID of the collateral pool that the position belongs to.
    /// @param _positionAddress The address of the position to redeem locked collateral from.
    /// @param _collateralReceiver The address to receive the redeemed collateral tokens.
    function redeemLockedCollateral(
        bytes32 _collateralPoolId,
        address _positionAddress,
        address _collateralReceiver,
        bytes calldata /* _data */
    ) external override {
        require(live == 0, "ShowStopper/still-live");
        require(_positionAddress == msg.sender || bookKeeper.positionWhitelist(_positionAddress, msg.sender) == 1, "ShowStopper/not-allowed");
        (uint256 _lockedCollateralAmount, uint256 _debtShare) = bookKeeper.positions(_collateralPoolId, _positionAddress);
        require(_debtShare == 0, "ShowStopper/debtShare-not-zero");
        require(_lockedCollateralAmount < 2 ** 255, "ShowStopper/overflow");
        bookKeeper.confiscatePosition(
            _collateralPoolId,
            _positionAddress,
            _collateralReceiver,
            address(systemDebtEngine),
            -_safeToInt256(_lockedCollateralAmount),
            0
        );
        emit LogRedeemLockedCollateral(_collateralPoolId, _collateralReceiver, _lockedCollateralAmount);
    }

    function _safeToInt256(uint256 _number) internal pure returns (int256) {
        require(int256(_number) >= 0, "ShowStopper/overflow");
        return int256(_number);
    }
}
