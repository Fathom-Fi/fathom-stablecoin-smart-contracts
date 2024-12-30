// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

interface IERC2612 {
    /// @notice Approve an address to spend the vault's shares.
    /// @param owner The address to approve.
    /// @param spender The address to approve.
    /// @param amount The amount of shares to approve.
    /// @param deadline The deadline for the permit.
    /// @param v The v component of the signature.
    /// @param r The r component of the signature.
    /// @param s The s component of the signature.
    /// @return True if the approval was successful.
    function permit(
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool);

    /// @notice EIP-2612 permit() domain separator.
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
