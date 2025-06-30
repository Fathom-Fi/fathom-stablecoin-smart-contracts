// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20Mintable is Ownable, ERC20 {
    uint8 private _decimals = 18;

    constructor(string memory _name, string memory _symbol) ERC20(_name, _symbol) {}

    function mint(address _to, uint256 _amount) external onlyOwner {
        _mint(_to, _amount);
    }

    function burn(address _address, uint256 _amount) public virtual {
        _burn(_address, _amount);
    }

    function setDecimals(uint8 _newDecimals) external onlyOwner {
        _decimals = _newDecimals;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }
}
