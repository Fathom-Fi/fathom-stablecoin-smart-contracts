// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity 0.8.17;

import "./IFathomVaultConfig.sol";

interface IFathomVault {
  function config() external view returns (IFathomVaultConfig);

  /// @dev Return the total ERC20 entitled to the token holders. Be careful of unaccrued interests.
  function totalToken() external view returns (uint256);

  /// @dev Returns the amount of tokens in existence.
  function totalSupply() external view returns (uint256);

  /// @dev Add more ERC20 to the bank. Hope to get some good returns.
  function deposit(uint256 amountToken) external payable;

  /// @dev Withdraw ERC20 from the bank by burning the share tokens.
  function withdraw(uint256 share) external;

  /// @dev Request funds from user through Vault
  function requestFunds(address targetedToken, uint256 amount) external;

  function token() external view returns (address);

  function approve(address spender, uint256 amount) external virtual returns (bool);
}
