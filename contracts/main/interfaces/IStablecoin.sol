// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IStablecoin is IERC20 {
    event Rename(string _name);

    function mint(address, uint256) external;

    function burn(address, uint256) external;

    function increaseAllowance(address, uint256) external returns (bool);

    function decreaseAllowance(address, uint256) external returns (bool);

    function rename(string memory) external;
}
