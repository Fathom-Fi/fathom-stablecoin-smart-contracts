task("fthm", "FTHM Token Info").setAction(async () => {
  const proxyWalletFactory = await ethers.getContractAt("ProxyWalletFactory", "0xA43529Ce149924051e9A56b2BE740AEDbA4A581a");
  const adminControls = await ethers.getContractAt("AdminControls", "0x32A5f5D0BdB48E0A3A79ec21364e2F9f3f6a23c5");
  const flashMintArbitrager = await ethers.getContractAt("FlashMintArbitrager", "0x25464a1Cf25D1b180a36417fAB9FFd9960627860");
  const bookKeeperFlashMintArbitrager = await ethers.getContractAt("BookKeeperFlashMintArbitrager", "0xf3D403DA1C8368Ce164dDA5bd316d582aC457a35");

  console.log(await proxyWalletFactory.owner());
  console.log(await adminControls.owner());
  console.log(await flashMintArbitrager.owner());
  console.log(await bookKeeperFlashMintArbitrager.owner());

  // const strategies = [
  //   ethers.utils.getAddress("0x66B45F20cE90D5164bf85C582002d3620C429496"),
  //   ethers.utils.getAddress("0x465aeF54f7a8d9fE22B74A27fcd922c95cAaD4Be"),
  //   ethers.utils.getAddress("0x524ae63AB2D30853578E75eA0A758E0DA2d59814"),
  //   ethers.utils.getAddress("0xfe5037504E0EF5eC2DfBEEA03f9d9cB43580EF23")
  // ]
  // const accessControlConfig = await ethers.getContractAt("AccessControlConfig", "0x2cD89769a2D9d992790e76c6A9f55c39fdf2FDc2");
  // const collateralTokenAdapterXDC = await ethers.getContractAt("CollateralTokenAdapter", "0x2fc7e65023aFF27FA61A573B5C8E3fDe3CE9ef79");
  // const collateralTokenAdapterCGO = await ethers.getContractAt("CollateralTokenAdapter", "0x30c64659AADD8C92328859A1CEE99721083A8E0f");

  // for (let i = 0; i < strategies.length; i++) {
  //   console.log("For Strategy", strategies[i]);
  //   console.log("has ownerRole", await accessControlConfig.hasRole(await accessControlConfig.OWNER_ROLE(), strategies[i]));
  //   console.log("has govRole", await accessControlConfig.hasRole(await accessControlConfig.GOV_ROLE(), strategies[i]));
  //   console.log("has priceOracle", await accessControlConfig.hasRole(await accessControlConfig.PRICE_ORACLE_ROLE(), strategies[i]));
  //   console.log("has adapterRole", await accessControlConfig.hasRole(await accessControlConfig.ADAPTER_ROLE(), strategies[i]));
  //   console.log("has liquidationEngineRole", await accessControlConfig.hasRole(await accessControlConfig.LIQUIDATION_ENGINE_ROLE(), strategies[i]));
  //   console.log("has stabilityFeeCollector", await accessControlConfig.hasRole(await accessControlConfig.STABILITY_FEE_COLLECTOR_ROLE(), strategies[i]));
  //   console.log("has showStopper", await accessControlConfig.hasRole(await accessControlConfig.SHOW_STOPPER_ROLE(), strategies[i]));
  //   console.log("has positionManager", await accessControlConfig.hasRole(await accessControlConfig.POSITION_MANAGER_ROLE(), strategies[i]));
  //   console.log("has mintableRole", await accessControlConfig.hasRole(await accessControlConfig.MINTABLE_ROLE(), strategies[i]));
  //   console.log("has bookKeeperRole", await accessControlConfig.hasRole(await accessControlConfig.BOOK_KEEPER_ROLE(), strategies[i]));
  //   console.log("has collateralManagerRole", await accessControlConfig.hasRole(await accessControlConfig.COLLATERAL_MANAGER_ROLE(), strategies[i]));
  //   console.log("is whitelisted in xdc collateral token adapter", await collateralTokenAdapterXDC.whiteListed(strategies[i]));
  //   console.log("is whitelisted cgo collateral token adapter", await collateralTokenAdapterCGO.whiteListed(strategies[i]));
  //   console.log('************************************************');
  //   console.log(`\n`);
  // }
});

module.exports = {};
