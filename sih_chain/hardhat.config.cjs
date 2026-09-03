require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.19",
  networks: {
    sepolia: {
      url: "https://rpc.sepolia.org",
      chainId: 11155111,
      accounts: ["a161be1df7f5a021bba1b2045763fd3dda69277dcecb3cd68a954fbdb28cf821"],
    }
  }
};