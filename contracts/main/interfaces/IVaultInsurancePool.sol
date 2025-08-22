// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.17;

interface IVaultInsurancePool {
    struct InsuranceStake {
        uint256 amount; // Amount staked
        uint256 stakeTime; // When stake was made
        uint256 lastRewardClaim; // Last reward claim time
        bool isActive; // Whether stake is active
    }

    struct ClaimRequest {
        bytes32 collateralPoolId;
        address positionOwner;
        uint256 lossAmount; // Amount of loss to be covered
        uint256 requestTime;
        bool isApproved;
        bool isPaid;
        string reason; // Reason for the claim
    }

    struct PoolStats {
        uint256 totalStaked; // Total amount staked in pool
        uint256 totalClaims; // Total claims paid out
        uint256 availableFunds; // Available funds for claims
        uint256 reserveRatio; // Reserve ratio requirement
        uint256 stakingRewardRate; // Annual reward rate for stakers
        uint256 lastUpdateTime; // Last stats update time
    }

    event LogStakeDeposited(address indexed staker, uint256 amount, uint256 totalStaked);
    event LogStakeWithdrawn(address indexed staker, uint256 amount, uint256 totalStaked);
    event LogRewardsClaimed(address indexed staker, uint256 rewardAmount);
    event LogClaimSubmitted(bytes32 indexed claimId, address indexed claimant, uint256 amount);
    event LogClaimApproved(bytes32 indexed claimId, uint256 amount);
    event LogClaimPaid(bytes32 indexed claimId, address indexed recipient, uint256 amount);
    event LogReserveRatioUpdated(uint256 oldRatio, uint256 newRatio);
    event LogStakingRewardRateUpdated(uint256 oldRate, uint256 newRate);

    function stake() external payable returns (bool);
    function withdraw(uint256 _amount) external returns (bool);
    function claimRewards() external returns (uint256);
    
    function submitClaim(
        bytes32 _collateralPoolId,
        address _positionOwner,
        uint256 _lossAmount,
        string calldata _reason
    ) external returns (bytes32 claimId);
    
    function approveClaim(bytes32 _claimId) external returns (bool);
    function rejectClaim(bytes32 _claimId, string calldata _reason) external returns (bool);
    function payClaim(bytes32 _claimId) external returns (bool);
    
    function calculateStakeRewards(address _staker) external view returns (uint256);
    function calculatePendingRewards(address _staker) external view returns (uint256);
    function getStakeInfo(address _staker) external view returns (InsuranceStake memory);
    function getClaimInfo(bytes32 _claimId) external view returns (ClaimRequest memory);
    function getPoolStats() external view returns (PoolStats memory);
    
    function isClaimEligible(
        bytes32 _collateralPoolId,
        address _positionOwner,
        uint256 _lossAmount
    ) external view returns (bool, string memory reason);
    
    function setReserveRatio(uint256 _newRatio) external;
    function setStakingRewardRate(uint256 _newRate) external;
    function setClaimTimeLimit(uint256 _timeLimit) external;
    function emergencyWithdraw() external;
}
