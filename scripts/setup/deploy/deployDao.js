const { ethers } = require("hardhat");
const provider = ethers.provider;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const PROPOSER_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("PROPOSER_ROLE"));
const EXECUTOR_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("EXECUTOR_ROLE"));
const TIMELOCK_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("TIMELOCK_ADMIN_ROLE"));

async function deployDao(getNamedAccounts, deployments) {
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  // Deploy token for voting
  // Token should only be deployed for local tests, otherwise use the FTHM token deployed on mainnet/testnet
  await deploy("GovToken", {
    from: deployer,
    args: [],
    log: true,
  });

  const GovToken = await deployments.get("GovToken");
  const govToken = await ethers.getContractAt("GovToken", GovToken.address);
  await govToken.mint(deployer, ethers.utils.parseEther("100"));

  await govToken.connect(provider.getSigner(deployer)).delegate(deployer);

  // Deploy Timelock
  // initial minimum delay for operations
  // after a vote passes, we have 1 day before we can enact
  const MIN_DELAY = ethers.BigNumber.from("3600"); // 1 hour TODO: check this value

  await deploy("Timelock", {
    from: deployer,
    args: [
      MIN_DELAY,
      [], // proposers
      [], // executors
    ],
    log: true,
  });

  const Timelock = await deployments.get("Timelock");

  // Deploy Governor
  await deploy("ProtocolGovernor", {
    from: deployer,
    args: [GovToken.address, Timelock.address],
    log: true,
  });

  const ProtocolGovernor = await deployments.get("ProtocolGovernor");

  const timelock = await ethers.getContractAt("Timelock", Timelock.address);

  await timelock.grantRole(PROPOSER_ROLE, ProtocolGovernor.address); // with this we are saying that everyone can propose, but only governor can queue
  await timelock.grantRole(EXECUTOR_ROLE, ZERO_ADDRESS); // anybody can execute and pass proposals
  await timelock.revokeRole(TIMELOCK_ADMIN_ROLE, deployer); // deployer will no longer be the admin of the timelock
}

module.exports = {
  deployDao,
};
