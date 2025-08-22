// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "../interfaces/IVaultInsurancePool.sol";
import "../interfaces/IBookKeeper.sol";
import "../interfaces/IAccessControlConfig.sol";
import "../utils/CommonMath.sol";

/**
 * @title VaultInsurancePool
 * @notice Community-funded insurance pool that protects users from unexpected losses
 * due to smart contract risks, extreme market events, or system failures
 */
contract VaultInsurancePool is 
    CommonMath,
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable, 
    IVaultInsurancePool 
{
    uint256 public constant MIN_STAKE_AMOUNT = 1e15; // 0.001 ETH minimum
    uint256 public constant MIN_RESERVE_RATIO = 2000; // 20% in basis points
    uint256 public constant MAX_RESERVE_RATIO = 9000; // 90% in basis points
    uint256 public constant MAX_STAKING_REWARD_RATE = 5000; // 50% annual in basis points
    uint256 public constant CLAIM_TIME_LIMIT = 30 days;
    uint256 public constant WITHDRAWAL_LOCK_PERIOD = 7 days;
    uint256 public constant BASIS_POINTS = 10000;
    
    IBookKeeper public bookKeeper;
    IAccessControlConfig public accessControlConfig;
    
    mapping(address => InsuranceStake) public stakes;
    mapping(bytes32 => ClaimRequest) public claims;
    mapping(address => uint256) public withdrawalRequests; // address => request time
    
    PoolStats public poolStats;
    uint256 public claimTimeLimit;
    uint256 public nextClaimId;
    
    address[] public stakers; // For easier iteration
    mapping(address => bool) public isStaker;

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

    modifier onlyClaimManager() {
        require(
            accessControlConfig.hasRole(accessControlConfig.OWNER_ROLE(), msg.sender) ||
                accessControlConfig.hasRole(accessControlConfig.GOV_ROLE(), msg.sender) ||
                accessControlConfig.hasRole(accessControlConfig.LIQUIDATION_ENGINE_ROLE(), msg.sender),
            "!claimManagerRole"
        );
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _bookKeeper,
        uint256 _reserveRatio,
        uint256 _stakingRewardRate,
        uint256 _claimTimeLimit
    ) external initializer {
        PausableUpgradeable.__Pausable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        
        require(_bookKeeper != address(0), "VaultInsurancePool/invalid-bookkeeper");
        require(_reserveRatio >= MIN_RESERVE_RATIO && _reserveRatio <= MAX_RESERVE_RATIO, 
                "VaultInsurancePool/invalid-reserve-ratio");
        require(_stakingRewardRate <= MAX_STAKING_REWARD_RATE, "VaultInsurancePool/invalid-reward-rate");
        require(_claimTimeLimit <= CLAIM_TIME_LIMIT, "VaultInsurancePool/invalid-claim-time-limit");
        
        bookKeeper = IBookKeeper(_bookKeeper);
        accessControlConfig = IAccessControlConfig(bookKeeper.accessControlConfig());
        
        poolStats.reserveRatio = _reserveRatio;
        poolStats.stakingRewardRate = _stakingRewardRate;
        poolStats.lastUpdateTime = block.timestamp;
        
        claimTimeLimit = _claimTimeLimit;
        nextClaimId = 1;
    }

    function stake() external payable override nonReentrant whenNotPaused returns (bool) {
        require(msg.value >= MIN_STAKE_AMOUNT, "VaultInsurancePool/insufficient-stake");
        
        InsuranceStake storage userStake = stakes[msg.sender];
        
        // Claim any pending rewards before updating stake
        if (userStake.amount > 0) {
            _claimRewards(msg.sender);
        }
        
        // Update stake
        userStake.amount += msg.value;
        userStake.stakeTime = userStake.stakeTime == 0 ? block.timestamp : userStake.stakeTime;
        userStake.lastRewardClaim = block.timestamp;
        userStake.isActive = true;
        
        // Add to stakers list if new staker
        if (!isStaker[msg.sender]) {
            stakers.push(msg.sender);
            isStaker[msg.sender] = true;
        }
        
        // Update pool stats
        poolStats.totalStaked += msg.value;
        poolStats.availableFunds += msg.value;
        poolStats.lastUpdateTime = block.timestamp;
        
        emit LogStakeDeposited(msg.sender, msg.value, poolStats.totalStaked);
        return true;
    }

    function withdraw(uint256 _amount) external override nonReentrant whenNotPaused returns (bool) {
        InsuranceStake storage userStake = stakes[msg.sender];
        require(userStake.isActive && userStake.amount >= _amount, "VaultInsurancePool/insufficient-stake");
        
        // Check withdrawal lock period for new stakes
        require(block.timestamp >= userStake.stakeTime + WITHDRAWAL_LOCK_PERIOD, 
                "VaultInsurancePool/withdrawal-locked");
        
        // Ensure sufficient reserves remain
        uint256 requiredReserves = (poolStats.totalClaims * poolStats.reserveRatio) / BASIS_POINTS;
        require(poolStats.availableFunds - _amount >= requiredReserves, 
                "VaultInsurancePool/insufficient-reserves");
        
        // Claim any pending rewards
        _claimRewards(msg.sender);
        
        // Update stake
        userStake.amount -= _amount;
        if (userStake.amount == 0) {
            userStake.isActive = false;
        }
        
        // Update pool stats
        poolStats.totalStaked -= _amount;
        poolStats.availableFunds -= _amount;
        poolStats.lastUpdateTime = block.timestamp;
        
        // Transfer funds
        payable(msg.sender).transfer(_amount);
        
        emit LogStakeWithdrawn(msg.sender, _amount, poolStats.totalStaked);
        return true;
    }

    function claimRewards() external override nonReentrant whenNotPaused returns (uint256) {
        return _claimRewards(msg.sender);
    }

    function _claimRewards(address _staker) internal returns (uint256) {
        uint256 rewards = calculatePendingRewards(_staker);
        if (rewards == 0) {
            return 0;
        }
        
        InsuranceStake storage userStake = stakes[_staker];
        userStake.lastRewardClaim = block.timestamp;
        
        // Transfer rewards (rewards would typically come from protocol fees)
        // For now, this is a placeholder - in production, rewards would be funded separately
        if (address(this).balance >= rewards) {
            payable(_staker).transfer(rewards);
            emit LogRewardsClaimed(_staker, rewards);
        }
        
        return rewards;
    }

    function submitClaim(
        bytes32 _collateralPoolId,
        address _positionOwner,
        uint256 _lossAmount,
        string calldata _reason
    ) external override nonReentrant whenNotPaused returns (bytes32 claimId) {
        require(_lossAmount > 0, "VaultInsurancePool/invalid-loss-amount");
        
        // Verify claim eligibility
        (bool eligible, string memory reason) = isClaimEligible(_collateralPoolId, _positionOwner, _lossAmount);
        require(eligible, reason);
        
        claimId = bytes32(nextClaimId++);
        
        claims[claimId] = ClaimRequest({
            collateralPoolId: _collateralPoolId,
            positionOwner: _positionOwner,
            lossAmount: _lossAmount,
            requestTime: block.timestamp,
            isApproved: false,
            isPaid: false,
            reason: _reason
        });
        
        emit LogClaimSubmitted(claimId, msg.sender, _lossAmount);
        return claimId;
    }

    function approveClaim(bytes32 _claimId) external override onlyClaimManager returns (bool) {
        ClaimRequest storage claim = claims[_claimId];
        require(claim.requestTime > 0, "VaultInsurancePool/invalid-claim");
        require(!claim.isApproved, "VaultInsurancePool/already-approved");
        require(block.timestamp <= claim.requestTime + claimTimeLimit, "VaultInsurancePool/claim-expired");
        
        // Verify sufficient funds
        require(poolStats.availableFunds >= claim.lossAmount, "VaultInsurancePool/insufficient-funds");
        
        claim.isApproved = true;
        
        emit LogClaimApproved(_claimId, claim.lossAmount);
        return true;
    }

    function rejectClaim(bytes32 _claimId, string calldata _reason) external override onlyClaimManager returns (bool) {
        ClaimRequest storage claim = claims[_claimId];
        require(claim.requestTime > 0, "VaultInsurancePool/invalid-claim");
        require(!claim.isApproved && !claim.isPaid, "VaultInsurancePool/claim-already-processed");
        
        // Mark claim as rejected by setting request time to 0
        claim.requestTime = 0;
        
        // Log rejection reason
        emit LogClaimApproved(_claimId, 0); // 0 amount indicates rejection
        return true;
    }

    function payClaim(bytes32 _claimId) external override onlyClaimManager nonReentrant returns (bool) {
        ClaimRequest storage claim = claims[_claimId];
        require(claim.isApproved && !claim.isPaid, "VaultInsurancePool/claim-not-payable");
        require(poolStats.availableFunds >= claim.lossAmount, "VaultInsurancePool/insufficient-funds");
        
        claim.isPaid = true;
        
        // Update pool stats
        poolStats.totalClaims += claim.lossAmount;
        poolStats.availableFunds -= claim.lossAmount;
        poolStats.lastUpdateTime = block.timestamp;
        
        // Transfer funds to position owner
        payable(claim.positionOwner).transfer(claim.lossAmount);
        
        emit LogClaimPaid(_claimId, claim.positionOwner, claim.lossAmount);
        return true;
    }

    function calculateStakeRewards(address _staker) public view override returns (uint256) {
        InsuranceStake memory userStake = stakes[_staker];
        if (!userStake.isActive || userStake.amount == 0) {
            return 0;
        }
        
        uint256 timeStaked = block.timestamp - userStake.stakeTime;
        uint256 annualReward = (userStake.amount * poolStats.stakingRewardRate) / BASIS_POINTS;
        
        return (annualReward * timeStaked) / 365 days;
    }

    function calculatePendingRewards(address _staker) public view override returns (uint256) {
        InsuranceStake memory userStake = stakes[_staker];
        if (!userStake.isActive || userStake.amount == 0) {
            return 0;
        }
        
        uint256 timeSinceLastClaim = block.timestamp - userStake.lastRewardClaim;
        uint256 annualReward = (userStake.amount * poolStats.stakingRewardRate) / BASIS_POINTS;
        
        return (annualReward * timeSinceLastClaim) / 365 days;
    }

    function getStakeInfo(address _staker) external view override returns (InsuranceStake memory) {
        return stakes[_staker];
    }

    function getClaimInfo(bytes32 _claimId) external view override returns (ClaimRequest memory) {
        return claims[_claimId];
    }

    function getPoolStats() external view override returns (PoolStats memory) {
        return poolStats;
    }

    function isClaimEligible(
        bytes32 _collateralPoolId,
        address _positionOwner,
        uint256 _lossAmount
    ) public view override returns (bool, string memory reason) {
        // Check if position exists
        (uint256 lockedCollateral, uint256 debtShare) = bookKeeper.positions(_collateralPoolId, _positionOwner);
        if (lockedCollateral == 0 && debtShare == 0) {
            return (false, "Position does not exist");
        }
        
        // Check if pool has sufficient funds
        if (poolStats.availableFunds < _lossAmount) {
            return (false, "Insufficient pool funds");
        }
        
        // Check reserve ratio requirements
        uint256 requiredReserves = ((poolStats.totalClaims + _lossAmount) * poolStats.reserveRatio) / BASIS_POINTS;
        if (poolStats.availableFunds - _lossAmount < requiredReserves) {
            return (false, "Would violate reserve ratio");
        }
        
        return (true, "Eligible for coverage");
    }

    function setReserveRatio(uint256 _newRatio) external override onlyOwner {
        require(_newRatio >= MIN_RESERVE_RATIO && _newRatio <= MAX_RESERVE_RATIO, 
                "VaultInsurancePool/invalid-reserve-ratio");
        uint256 oldRatio = poolStats.reserveRatio;
        poolStats.reserveRatio = _newRatio;
        emit LogReserveRatioUpdated(oldRatio, _newRatio);
    }

    function setStakingRewardRate(uint256 _newRate) external override onlyOwner {
        require(_newRate <= MAX_STAKING_REWARD_RATE, "VaultInsurancePool/invalid-reward-rate");
        uint256 oldRate = poolStats.stakingRewardRate;
        poolStats.stakingRewardRate = _newRate;
        emit LogStakingRewardRateUpdated(oldRate, _newRate);
    }

    function setClaimTimeLimit(uint256 _timeLimit) external override onlyOwner {
        require(_timeLimit <= CLAIM_TIME_LIMIT, "VaultInsurancePool/invalid-time-limit");
        claimTimeLimit = _timeLimit;
    }

    function emergencyWithdraw() external override onlyOwner {
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }

    function pause() external onlyOwnerOrGov {
        _pause();
    }

    function unpause() external onlyOwnerOrGov {
        _unpause();
    }

    // View functions for analytics
    function getTotalStakers() external view returns (uint256) {
        uint256 activeStakers = 0;
        for (uint256 i = 0; i < stakers.length; i++) {
            if (stakes[stakers[i]].isActive) {
                activeStakers++;
            }
        }
        return activeStakers;
    }

    function getPoolUtilization() external view returns (uint256) {
        if (poolStats.totalStaked == 0) {
            return 0;
        }
        return (poolStats.totalClaims * BASIS_POINTS) / poolStats.totalStaked;
    }

    // Accept ETH deposits
    receive() external payable {
        poolStats.availableFunds += msg.value;
    }
}
