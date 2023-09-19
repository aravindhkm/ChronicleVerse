const hre = require("hardhat");

async function main() {  
  const accounts = await hre.ethers.getSigners();
  const admin = accounts[0].address;
  console.log("Accounts", admin);

  //// ************ DEPLOY TREASURY **************/////

  const chronicleVerseTreasury = await hre.ethers.getContractFactory("ChronicleVerseTreasury");
  const treasuryInstance = await chronicleVerseTreasury.deploy(admin);
  await treasuryInstance.deployed();
  chronicleVerseTreasuryAddress = treasuryInstance.address;
  console.log("chronicleVerseTreasuryAddress deployed to:", chronicleVerseTreasuryAddress); 

  await hre.run("verify:verify", {
    address: chronicleVerseTreasuryAddress,
    constructorArguments: [admin],
  });


  //// ************ DEPLOY NFT **************/////

  // const chronicleVerseTreasuryAddress = "0x3E641DbbbFaFa902eB12958ED32cd82fF1239fd7";
  const name = "IWC NFT TEST";
  const symbol = "IWC_NFT";
  const baseUri =  "https://ipfs.io/ipfs/";

  const chronicleVerseNFT = await hre.ethers.getContractFactory("ChronicleVerseNFT");
  const chronicleVerseNFTInstance = await chronicleVerseNFT.deploy(chronicleVerseTreasuryAddress,name,symbol,baseUri);
  await chronicleVerseNFTInstance.deployed();
  chronicleVerseNFTAddress = chronicleVerseNFTInstance.address;
  console.log("chronicleVerseNFTAddress deployed to:", chronicleVerseNFTAddress); 

  await hre.run("verify:verify", {
    address: chronicleVerseNFTAddress,
    constructorArguments: [chronicleVerseTreasuryAddress,name,symbol,baseUri],
  });
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
