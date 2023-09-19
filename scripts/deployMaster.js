const hre = require("hardhat");

async function main() {  
  const accounts = await hre.ethers.getSigners();
  const admin = accounts[0].address;
  console.log("Accounts", admin);

  //// ************ DEPLOY TREASURY **************/////

  const chronicleVerseTreasury = "0x3E641DbbbFaFa902eB12958ED32cd82fF1239fd7"

  const chronicleVerseMaster = await hre.ethers.getContractFactory("ChronicleVerseMaster");
  const masterInstance = await chronicleVerseMaster.deploy(chronicleVerseTreasury);
  await masterInstance.deployed();
  chronicleVerseMasterAddress = masterInstance.address;
  console.log("chronicleVerseMasterAddress deployed to:", chronicleVerseMasterAddress); 

  await hre.run("verify:verify", {
    address: chronicleVerseMasterAddress,
    constructorArguments: [chronicleVerseTreasury],
  });

}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
