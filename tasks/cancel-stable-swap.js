task("cancel-stable-swap", "Cancel Stable Swap")
  .setAction(async () => {
    const stableSwap = await ethers.getContractAt("StableSwapModule", "0x42c06188B8C03769A1F73B3f31b259271ee3B981");
    const accessControlConfig = await ethers.getContractAt("AccessControlConfig", "0x2cD89769a2D9d992790e76c6A9f55c39fdf2FDc2");
    
    const hasPositionManagerRole = await accessControlConfig.hasRole(await accessControlConfig.POSITION_MANAGER_ROLE(), stableSwap.address);
    const hasCollateralManagerRole = await accessControlConfig.hasRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), stableSwap.address);

    console.log("Does StableSwapModule have position manager role?", hasPositionManagerRole);
    console.log("Does StableSwapModule have collateral manager role?", hasCollateralManagerRole);
  
    // Revoke roles
    if (hasPositionManagerRole) {
      await accessControlConfig.revokeRole(await accessControlConfig.POSITION_MANAGER_ROLE(), stableSwap.address);
    }
    if (hasCollateralManagerRole) {
      await accessControlConfig.revokeRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), stableSwap.address);
    }

    // Pause the contract
    await stableSwap.pause();
  });

module.exports = {};
