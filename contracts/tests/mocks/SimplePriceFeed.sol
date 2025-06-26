// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import "../../main/interfaces/IPriceFeed.sol";
import "../../main/interfaces/IAccessControlConfig.sol";

contract SimplePriceFeed is PausableUpgradeable, AccessControlUpgradeable, IPriceFeed {
    IAccessControlConfig public accessControlConfig;

    uint256 public price;
    uint256 public lastUpdateTS;
    bytes32 public poolId;

    uint256 public priceLife;

    function initialize(address _accessControlConfig) external initializer {
        PausableUpgradeable.__Pausable_init();
        AccessControlUpgradeable.__AccessControl_init();

        priceLife = 365 days; // [seconds] how old the price is considered stale, default 1 day

        accessControlConfig = IAccessControlConfig(_accessControlConfig);
    }

    modifier onlyOwner() {
        require(accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender), "!ownerRole");
        _;
    }

    modifier onlyOwnerOrGov() {
        require(
            accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender) ||
                accessControlConfig.hasRole(accessControlConfig.GOV_ROLE(), msg.sender),
            "!(ownerRole or govRole)"
        );
        _;
    }

    event LogSetPrice(address indexed _caller, uint256 _price, uint256 indexed _lastUpdate);

    /// @dev access: OWNER_ROLE
    function setPrice(uint256 _price) external onlyOwner {
        price = _price;
        lastUpdateTS = block.timestamp;
        emit LogSetPrice(msg.sender, price, lastUpdateTS);
    }

    function setPriceLife(uint256 _second) external onlyOwner {
        require(_second >= 1 hours && _second <= 365 days, "SimplePriceFeed/bad-price-life");
        priceLife = _second;
        emit LogSetPriceLife(msg.sender, _second);
    }

    function setPoolId(bytes32 _poolId) external {
        poolId = _poolId;
    }

    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    function readPrice() external view override returns (uint256) {
        return price;
    }

    function peekPrice() external view override returns (uint256, bool) {
        return (price, _isPriceOk());
    }

    function isPriceOk() external view override returns (bool) {
        return _isPriceOk();
    }

    function isPriceFresh() external view override returns (bool) {
        return lastUpdateTS >= block.timestamp - priceLife;
    }

    function _isPriceOk() internal view returns (bool) {
        return this.isPriceFresh() && !paused();
    }
}
