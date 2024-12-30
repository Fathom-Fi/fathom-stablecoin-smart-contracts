// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "../interfaces/IStablecoin.sol";
import "../interfaces/IERC2612.sol";

contract FathomStablecoin is IStablecoin, IERC2612, AccessControlUpgradeable {
    bytes32 public constant OWNER_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // solhint-disable-next-line const-name-snakecase
    string public constant version = "1";
    // solhint-disable-next-line const-name-snakecase
    uint8 public constant decimals = 18;

    /// @notice EIP-2612 permit() typehashes
    bytes32 public constant DOMAIN_TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PERMIT_TYPE_HASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    string public name; // Fathom USD Stablecoin
    string public symbol; // FXD
    uint256 public totalSupply;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice EIP-2612 permit() nonces
    mapping(address => uint256) public nonces;

    constructor() {
        _disableInitializers();
    }

    function initialize(string memory _name, string memory _symbol) external initializer {
        AccessControlUpgradeable.__AccessControl_init();

        name = _name;
        symbol = _symbol;

        _setupRole(OWNER_ROLE, msg.sender);
    }

    /// @notice Transfer `_wad` amount of tokens from `msg.sender` to `_dst`.
    /// @param _dst The address to transfer tokens to.
    /// @param _wad The amount of tokens to transfer.
    /// @return A boolean value indicating whether the operation succeeded.
    function transfer(address _dst, uint256 _wad) external override returns (bool) {
        return transferFrom(msg.sender, _dst, _wad);
    }

    /// @notice Creates `_wad` amount of new tokens and assigns them to `_usr`, increasing the total supply.
    /// @dev This function can only be called by addresses with the minter role.
    /// @param _usr The address to assign the new tokens to.
    /// @param _wad The amount of new tokens to create.
    function mint(address _usr, uint256 _wad) external override {
        require(hasRole(MINTER_ROLE, msg.sender), "!minterRole");

        balanceOf[_usr] += _wad;
        totalSupply += _wad;
        emit Transfer(address(0), _usr, _wad);
    }

    /// @notice Destroys `_wad` amount tokens from `_usr`, reducing the total supply.
    /// @dev This function can only be called by `_usr` or an approved address.
    /// @param _usr The address to burn tokens from.
    /// @param _wad The amount of tokens to burn.
    function burn(address _usr, uint256 _wad) external override {
        require(balanceOf[_usr] >= _wad, "FathomStablecoin/insufficient-balance");
        if (_usr != msg.sender && allowance[_usr][msg.sender] != type(uint).max) {
            require(allowance[_usr][msg.sender] >= _wad, "FathomStablecoin/insufficient-allowance");
            allowance[_usr][msg.sender] -= _wad;
        }
        balanceOf[_usr] -= _wad;
        totalSupply -= _wad;
        emit Transfer(_usr, address(0), _wad);
    }

    /// @notice Set `_wad` as the allowance of `_usr` over the `msg.sender`'s tokens.
    /// @param _usr The address which will spend the funds.
    /// @param _wad The amount of tokens to allow.
    /// @return A boolean value indicating whether the operation succeeded.
    function approve(address _usr, uint256 _wad) external override returns (bool) {
        _approve(msg.sender, _usr, _wad);
        return true;
    }

    /// @notice Increase the allowance of `_usr` over the `msg.sender`'s tokens by `_wad`.
    /// @param _usr The address which will spend the funds.
    /// @param _wad The amount of tokens to increase the allowance by.
    /// @return A boolean value indicating whether the operation succeeded.
    function increaseAllowance(address _usr, uint256 _wad) external override returns (bool) {
        _approve(msg.sender, _usr, allowance[msg.sender][_usr] + _wad);
        return true;
    }

    /// @notice Decrease the allowance of `_usr` over the `msg.sender`'s tokens by `_wad`.
    /// @param _usr The address which will spend the funds.
    /// @param _wad The amount of tokens to decrease the allowance by.
    /// @return A boolean value indicating whether the operation succeeded.
    function decreaseAllowance(address _usr, uint256 _wad) external override returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][_usr];
        require(currentAllowance >= _wad, "FathomStablecoin/decreased-allowance-below-zero");
        _approve(msg.sender, _usr, currentAllowance - _wad);

        return true;
    }

    /// @notice Transfer `_wad` tokens from `msg.sender` to `_usr`.
    /// @param _usr The address to transfer tokens to.
    /// @param _wad The amount of tokens to transfer.
    function push(address _usr, uint256 _wad) external {
        transferFrom(msg.sender, _usr, _wad);
    }

    /// @notice Transfer `_wad` tokens from `_usr` to `msg.sender`.
    /// @param _usr The address to transfer tokens from.
    /// @param _wad The amount of tokens to transfer.
    function pull(address _usr, uint256 _wad) external {
        transferFrom(_usr, msg.sender, _wad);
    }

    /// @notice Transfer `_wad` tokens from `_src` to `_dst`.
    /// @param _src The address to transfer tokens from.
    /// @param _dst The address to transfer tokens to.
    /// @param _wad The amount of tokens to transfer.
    function move(address _src, address _dst, uint256 _wad) external {
        transferFrom(_src, _dst, _wad);
    }

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
    ) external override returns (bool) {
        if (owner == address(0)) {
            revert ZeroAddress();
        }
        if (deadline < block.timestamp) {
            revert ERC20PermitExpired();
        }
        uint256 nonce = nonces[owner];
        nonces[owner]++;

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPE_HASH, owner, spender, amount, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress == address(0) || recoveredAddress != owner) {
            revert ERC20PermitInvalidSignature(recoveredAddress);
        }

        // Set the allowance to the specified amount
        _approve(owner, spender, amount);

        emit Approval(owner, spender, amount);
        return true;
    }

    /// @notice Transfer `_wad` amount of tokens from `_src` to `_dst`.
    /// @param _src The address to transfer tokens from.
    /// @param _dst The address to transfer tokens to.
    /// @param _wad The amount of tokens to transfer.
    /// @return A boolean value indicating whether the operation succeeded.
    function transferFrom(address _src, address _dst, uint256 _wad) public override returns (bool) {
        require(_wad > 0, "FathomStablecoin/zero-amount");
        require(_dst != address(0), "FathomStablecoin/zero-destination");
        uint256 currentAllowance = allowance[_src][msg.sender];
        require(balanceOf[_src] >= _wad, "FathomStablecoin/insufficient-balance");
        if (_src != msg.sender && currentAllowance != type(uint).max) {
            require(currentAllowance >= _wad, "FathomStablecoin/insufficient-allowance");
            _approve(_src, msg.sender, currentAllowance - _wad);
        }
        balanceOf[_src] -= _wad;
        balanceOf[_dst] += _wad;
        emit Transfer(_src, _dst, _wad);
        return true;
    }

    /// @notice EIP-2612 permit() domain separator.
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DOMAIN_TYPE_HASH,
                    keccak256(bytes(sharesName)), // "Fathom Vault" in the example
                    keccak256(bytes(apiVersion())), // API_VERSION in the example
                    block.chainid, // Current chain ID
                    address(this) // Address of the contract
                )
            );
    }

    function _approve(address _owner, address _spender, uint256 _amount) internal {
        require(_owner != address(0), "FathomStablecoin/approve-from-zero-address");
        require(_spender != address(0), "FathomStablecoin/approve-to-zero-address");

        allowance[_owner][_spender] = _amount;
        emit Approval(_owner, _spender, _amount);
    }
}
