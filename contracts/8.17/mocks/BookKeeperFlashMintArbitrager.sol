// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@alpaca-finance/alpaca-contract/contracts/6/protocol/apis/pancake/IPancakeRouter02.sol";

import "../interfaces/IBookKeeperFlashBorrower.sol";
import "../interfaces/IStableSwapModule.sol";
import "../interfaces/IStablecoinAdapter.sol";
import "../utils/SafeToken.sol";

contract BookKeeperFlashMintArbitrager is OwnableUpgradeable, IBookKeeperFlashBorrower {
  using SafeToken for address;
  address public stablecoin;

  struct LocalVars {
    address router;
    address stableSwapToken;
    IStableSwapModule stableSwapModule;
  }

  // --- Init ---
  function initialize(address _stablecoin) external initializer {
    // 1. Initialized all dependencies
    OwnableUpgradeable.__Ownable_init();

    stablecoin = _stablecoin;
  }

  uint256 constant RAY = 10**27;

  function onBookKeeperFlashLoan(
    address initiator,
    uint256 loanValue, // [rad]
    uint256 fee,
    bytes calldata data
  ) external override returns (bytes32) {
    LocalVars memory vars;
    (vars.router, vars.stableSwapToken, vars.stableSwapModule) = abi.decode(
      data,
      (address, address, IStableSwapModule)
    );
    address[] memory path = new address[](2);
    path[0] = stablecoin;
    path[1] = vars.stableSwapToken;

    uint256 loanAmount = loanValue / RAY;

    // 1. Swap AUSD to BUSD at a DEX
    vars.stableSwapModule.stablecoinAdapter().bookKeeper().whitelist(
      address(vars.stableSwapModule.stablecoinAdapter())
    );
    vars.stableSwapModule.stablecoinAdapter().withdraw(address(this), loanAmount, abi.encode(0));
    uint256 balanceBefore = vars.stableSwapToken.myBalance();
    stablecoin.safeApprove(vars.router, type(uint256).max);
    IPancakeRouter02(vars.router).swapExactTokensForTokens(loanAmount, 0, path, address(this), block.timestamp);
    stablecoin.safeApprove(vars.router, 0);
    uint256 balanceAfter = vars.stableSwapToken.myBalance();

    // 2. Swap BUSD to AUSD at StableSwapModule
    vars.stableSwapToken.safeApprove(address(vars.stableSwapModule.authTokenAdapter()), type(uint256).max);
    vars.stableSwapModule.swapTokenToStablecoin(address(this), balanceAfter - balanceBefore);
    vars.stableSwapToken.safeApprove(address(vars.stableSwapModule.authTokenAdapter()), 0);

    // 3. Approve AUSD for FlashMintModule
    stablecoin.safeApprove(address(vars.stableSwapModule.stablecoinAdapter()), loanAmount + (fee / RAY));
    vars.stableSwapModule.stablecoinAdapter().deposit(msg.sender, loanAmount + (fee / RAY), abi.encode(0));

    return keccak256("BookKeeperFlashBorrower.onBookKeeperFlashLoan");
  }
}
