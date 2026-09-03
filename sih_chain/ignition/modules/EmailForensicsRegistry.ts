import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const EmailForensicsRegistryModule = buildModule("EmailForensicsRegistryModule", (m) => {
  const registry = m.contract("EmailForensicsRegistry");

  return { registry };
});

export default EmailForensicsRegistryModule;
