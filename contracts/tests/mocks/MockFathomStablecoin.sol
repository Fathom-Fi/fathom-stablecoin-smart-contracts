// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "../../main/interfaces/IStablecoin.sol";

contract MockFathomStablecoin is IStablecoin, AccessControlUpgradeable {
    bytes32 public constant OWNER_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // solhint-disable-next-line const-name-snakecase
    string public constant version = "1";
    // solhint-disable-next-line const-name-snakecase
    uint8 public constant decimals = 18;

    string public name; // Fathom USD Stablecoin
    string public symbol; // FXD
    uint256 public totalSupply;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

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

    /// @notice Change the name of the token to `_name`.
    /// @dev Only callable by the owner.
    /// @param _name The new name of the token.
    function rename(string memory _name) external override {
        require(hasRole(OWNER_ROLE, msg.sender), "!OWNER_ROLE");
        name = _name;
        emit Rename(_name);
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

    function _approve(address _owner, address _spender, uint256 _amount) internal {
        require(_owner != address(0), "FathomStablecoin/approve-from-zero-address");
        require(_spender != address(0), "FathomStablecoin/approve-to-zero-address");

        allowance[_owner][_spender] = _amount;
        emit Approval(_owner, _spender, _amount);
    }
}
