// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "./IPriceFeed.sol";


interface ITWAPPriceFeed {
    event LogPriceUpdate(uint256 indexed timestamp, uint256 price, uint256 twapPrice);
    event LogWindowUpdate(uint256 oldWindow, uint256 newWindow);
    event LogObservationWindowUpdate(uint256 oldWindow, uint256 newWindow);

    // IPriceFeed functions
    function peekPrice() external returns (uint256, bool);
    function readPrice() external view returns (uint256);
    function isPriceOk() external view returns (bool);
    function isPriceFresh() external view returns (bool);
    function poolId() external view returns (bytes32);

    // TWAP-specific functions
    function updatePrice() external returns (bool);
    function getTWAPPrice() external view returns (uint256, bool);
    function getTWAPPriceFor(uint256 _window) external view returns (uint256, bool);
    function setWindow(uint256 _newWindow) external;
    function setObservationWindow(uint256 _newObservationWindow) external;
    function canUpdate() external view returns (bool);
}
