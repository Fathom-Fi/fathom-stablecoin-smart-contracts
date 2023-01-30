const { ethers } = require("ethers");

const { BigNumber } = require("ethers");
const { formatBytes32String } = require("ethers/lib/utils");

const COLLATERAL_POOL_ID = formatBytes32String("XDC");

const { AliceAddress } = require("../tests/helper/address");

const { WeiPerWad } = require("../tests/helper/unit");
const MaxUint256 = require("@ethersproject/constants");


const wipeAndUnlockXDC = async (proxyWallet, positionId, collateralAmount, stablecoinAmount) => {

  console.log("parial closePosition");


  const wipeAndUnlockXDCAbi = [
      "function wipeAndUnlockXDC(address _manager, address _xdcAdapter, address _stablecoinAdapter, uint256 _positionId, uint256 _collateralAmount, uint256 _stablecoinAmount, bytes calldata _data)"
  ];
  const wipeAndUnlockXDCIFace = new ethers.utils.Interface(wipeAndUnlockXDCAbi);
  const closeParialPositionCall = wipeAndUnlockXDCIFace.encodeFunctionData("wipeAndUnlockXDC", [
    "0xF1760BE07B3c3162Ff1782D4a619E8Fc2028a807", //Position Manager
    "0xd28a2B214F6b8047148e3CA323357766EC124061", //AnkrCollateralAdapter
    "0x0C57BeB61545B7899f2C6fCD5ECbC6c5D29be6cc", // StablecoinAdapter
      positionId,
      collateralAmount, // wad
      stablecoinAmount, // wad
      "0x00",
  ])
  // console.log(closeParialPositionCall);
  console.log(`Position Number ${positionId} closed`);
  await proxyWallet.execute(closeParialPositionCall, {gasLimit: 2000000});

}

module.exports = async function(deployer) {

  //making wallet
  // const proxyWalletRegistry = await ProxyWalletRegistry.at(stablecoinAddress.proxyWalletRegistry);
  const proxyWalletAsAlice = await artifacts.initializeInterfaceAt("ProxyWallet", "0xaB9E9e40841F97a260E9E9ccc1A809A4663b7733");

  await wipeAndUnlockXDC(proxyWalletAsAlice, 37, WeiPerWad.mul(2), WeiPerWad.mul(3));

};

// 2 FXD borrowed, 1 XDC paid.

// when partiially closing, 0.5 XDC 1 FXD will pay

//