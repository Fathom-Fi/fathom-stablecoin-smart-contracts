task("update-liquidation-strategy", "Replace current liquidation strategy with a new one")
  .addParam("newLiquidationStrategy", "The address of the new liquidation strategy")
  .setAction(async (taskArgs) => {
    const CollateralTokenAdapterXDC = await ethers.getContractAt("CollateralTokenAdapter", "0x2fc7e65023aFF27FA61A573B5C8E3fDe3CE9ef79");
    const CollateralTokenAdapterCGO = await ethers.getContractAt("CollateralTokenAdapter", "0x30c64659AADD8C92328859A1CEE99721083A8E0f");
    const currentLiquidationStrategy = ethers.utils.getAddress("0xc0AC2E5181F90fDa9E9264b5b1634B2c8bD88CDd");

    console.log("Is current Liquidation Strategy whitelisted in XDC Collateral Token Adapter", await CollateralTokenAdapterXDC.whiteListed(currentLiquidationStrategy));
    console.log("Is current Liquidation Strategy whitelisted in CGO Collateral Token Adapter", await CollateralTokenAdapterCGO.whiteListed(currentLiquidationStrategy));
  
    // Remove the current liquidation strategy from the whitelist
    await CollateralTokenAdapterXDC.removeFromWhitelist(currentLiquidationStrategy);
    await CollateralTokenAdapterCGO.removeFromWhitelist(currentLiquidationStrategy);
    console.log("Is current Liquidation Strategy whitelisted in XDC Collateral Token Adapter", await CollateralTokenAdapterXDC.whiteListed(currentLiquidationStrategy));
    console.log("Is current Liquidation Strategy whitelisted in CGO Collateral Token Adapter", await CollateralTokenAdapterCGO.whiteListed(currentLiquidationStrategy));

    // Add the new liquidation strategy to the whitelist
    await CollateralTokenAdapterXDC.addToWhitelist(taskArgs.newLiquidationStrategy);
    await CollateralTokenAdapterCGO.addToWhitelist(taskArgs.newLiquidationStrategy);
    console.log("Is new Liquidation Strategy whitelisted in XDC Collateral Token Adapter", await CollateralTokenAdapterXDC.whiteListed(taskArgs.newLiquidationStrategy));
    console.log("Is new Liquidation Strategy whitelisted in CGO Collateral Token Adapter", await CollateralTokenAdapterCGO.whiteListed(taskArgs.newLiquidationStrategy));
  });

module.exports = {};