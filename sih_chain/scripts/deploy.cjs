const hre = require("hardhat");

async function main() {
  console.log("Deploying EmailForensicsRegistry...");
  const Registry = await hre.ethers.getContractFactory("EmailForensicsRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  console.log("✅ Contract deployed to:", address);
  console.log("Copy this into config.py → CONTRACT_ADDRESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});