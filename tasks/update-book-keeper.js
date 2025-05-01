task("update-book-keeper", "Update Book Keeper")
  .addParam("proxyAdminAddress", "The address of the FathomProxyAdmin contract")
  .addParam("bookKeeperAddress", "The address of the BookKeeper Proxy contract")
  .setAction(async (taskArgs) => {
    const proxyAdmin = await ethers.getContractAt("FathomProxyAdmin", taskArgs.proxyAdminAddress);
    const bookKeeper = await ethers.getContractAt("BookKeeper", taskArgs.bookKeeperAddress);
  
    const BookKeeperV2 = await ethers.getContractFactory("BookKeeperV2");
    const bookKeeperV2 = await BookKeeperV2.deploy();
    await bookKeeperV2.deployed();

    console.log("BookKeeper Proxy address: ", bookKeeper.address);
    console.log("BookKeeper Proxy current implementation address: ", await proxyAdmin.getProxyImplementation(bookKeeper.address));
    console.log("BookKeeperV2 implementation address: ", bookKeeperV2.address);
    await proxyAdmin.upgrade(bookKeeper.address, bookKeeperV2.address);
    console.log("Upgrading BookKeeper to BookKeeperV2");
    console.log("BookKeeper Proxy new implementation address: ", await proxyAdmin.getProxyImplementation(bookKeeper.address));
  });

module.exports = {};
