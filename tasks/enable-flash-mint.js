task("enable-flash-mint", "Make flash minting public")
  .addParam("fmmAddress", "The address of the FlashMintModule contract")
  .setAction(async (taskArgs) => {
    const flashMintModule = await ethers.getContractAt("FlashMintModule", taskArgs.fmmAddress);
    console.log("Current isDecentralizedState: ", await flashMintModule.isDecentralizedState());
    await flashMintModule.setDecentralizedStatesStatus(true);
    /** Probably we should consider seeting the max flash loan close to the current market cap, current value is 1_000_000_000 FXD which is too big */
    // await flashMintModule.maxFlashLoan(ethers.utils.parseEther("1900000"));
  });

module.exports = {};
