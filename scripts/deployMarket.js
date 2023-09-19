const hre = require("hardhat");

async function main() {  
  const accounts = await hre.ethers.getSigners();
  const admin = accounts[0].address;
  console.log("Accounts", admin);

  //// ************ DEPLOY MARKET **************/////

  const chronicleVerseTreasury = "0x3E641DbbbFaFa902eB12958ED32cd82fF1239fd7"

  const chronicleVerseMarket = await hre.ethers.getContractFactory("ChronicleVerseMarket");
  const marketInstance = await chronicleVerseMarket.deploy(chronicleVerseTreasury);
  await marketInstance.deployed();
  chronicleVerseMarketAddress = marketInstance.address;
  console.log("chronicleVerseMarketAddress deployed to:", chronicleVerseMarketAddress); 
  
  await marketInstance.adminUpdateConfig("1000", "600", "1500", "500");
  await marketInstance.adminUpdateToken("0x0000000000000000000000000000000000000000", true);

  await hre.run("verify:verify", {
    address: chronicleVerseMarketAddress,
    constructorArguments: [chronicleVerseTreasury],
  });

}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
