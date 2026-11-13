
require("dotenv").config();

const { ethers } = require("ethers");

// 1. Connect to local Anvil fork of Sepolia
const provider = new ethers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

// 2. Anvil test accounts
const SENDER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const RECEIVER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

// 3. Sepolia USDC contract
const USDC_ADDRESS =
  "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

// 4. USDC contract functions and events
const usdcInterface = new ethers.Interface([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function balanceOf(address account) view returns (uint256)",
  "function totalSupply() view returns (uint256)",
  "event Transfer(address indexed from, address indexed to, uint256 value)"
]);

const usdc = new ethers.Contract(
  USDC_ADDRESS,
  usdcInterface,
  provider
);

// 5. Amount to transfer: 10 USDC
// USDC has 6 decimal places.
const AMOUNT = ethers.parseUnits("10", 6);

// 6. Main simulation function
async function main() {

  // Check network
  const network = await provider.getNetwork();

  if (network.chainId !== 11155111n) {
    throw new Error("Wrong network. Expected Sepolia.");
  }

  console.log("Connected to Anvil fork of Sepolia.");

  // Read balances before simulation
  const senderBefore = await usdc.balanceOf(SENDER);
  const receiverBefore = await usdc.balanceOf(RECEIVER);
  const supplyBefore = await usdc.totalSupply();

  console.log("\n--- BEFORE SIMULATION ---");

  console.log(
    "Sender:",
    ethers.formatUnits(senderBefore, 6),
    "USDC"
  );

  console.log(
    "Receiver:",
    ethers.formatUnits(receiverBefore, 6),
    "USDC"
  );

  if (senderBefore < AMOUNT) {
    throw new Error("Sender has insufficient USDC.");
  }

  // Encode the USDC transfer function call
  const transferData = usdcInterface.encodeFunctionData(
    "transfer",
    [RECEIVER, AMOUNT]
  );

  // Encode sender balance query
  const senderBalanceData = usdcInterface.encodeFunctionData(
    "balanceOf",
    [SENDER]
  );

  // Encode receiver balance query
  const receiverBalanceData = usdcInterface.encodeFunctionData(
    "balanceOf",
    [RECEIVER]
  );

  // Encode total supply query
  const supplyData = usdcInterface.encodeFunctionData(
    "totalSupply"
  );

  // 7. Prepare eth_simulateV1 request
  const simulationPayload = {
    blockStateCalls: [
      {
        calls: [
          {
            from: SENDER,
            to: USDC_ADDRESS,
            gas: "0x186a0",
            data: transferData
          },
          {
            from: SENDER,
            to: USDC_ADDRESS,
            gas: "0x186a0",
            data: senderBalanceData
          },
          {
            from: SENDER,
            to: USDC_ADDRESS,
            gas: "0x186a0",
            data: receiverBalanceData
          },
          {
            from: SENDER,
            to: USDC_ADDRESS,
            gas: "0x186a0",
            data: supplyData
          }
        ]
      }
    ],
    validation: false
  };

  console.log("\nSimulating 10 USDC transfer...");

  // Execute simulation
  const result = await provider.send(
    "eth_simulateV1",
    [simulationPayload, "latest"]
  );

  // 8. Validate response
  if (!Array.isArray(result) || !result[0]) {
    throw new Error("Unexpected simulation response.");
  }

  const calls = result[0].calls;

  if (!calls || calls.length !== 4) {
    throw new Error("Unexpected number of simulated calls.");
  }

  // Check each simulated call
  console.log("\n--- CALL STATUS ---");

  const callNames = [
    "USDC transfer",
    "Read sender balance",
    "Read receiver balance",
    "Read total supply"
  ];

  calls.forEach((call, index) => {
    console.log(
      callNames[index] + ":",
      call.status === "0x1" ? "SUCCESS" : "FAILED"
    );

    if (call.error) {
      console.log("Error:", call.error.message);
    }
  });

  if (calls.some(call => call.status !== "0x1")) {
    throw new Error("At least one simulated call failed.");
  }

  // 9. Decode balances after simulated transfer
  const senderAfter = usdcInterface.decodeFunctionResult(
    "balanceOf",
    calls[1].returnData
  )[0];

  const receiverAfter = usdcInterface.decodeFunctionResult(
    "balanceOf",
    calls[2].returnData
  )[0];

  const supplyAfter = usdcInterface.decodeFunctionResult(
    "totalSupply",
    calls[3].returnData
  )[0];

  // 10. Inspect Transfer event
  const allLogs = calls.flatMap(call => call.logs || []);

  const transferTopic = ethers.id(
    "Transfer(address,address,uint256)"
  );

  let eventMatches = false;

  if (allLogs.length === 1) {
    const log = allLogs[0];

    if (
      log.address.toLowerCase() === USDC_ADDRESS.toLowerCase() &&
      log.topics[0] === transferTopic &&
      log.topics.length === 3
    ) {
      const loggedFrom = ethers.getAddress(
        "0x" + log.topics[1].slice(-40)
      );

      const loggedTo = ethers.getAddress(
        "0x" + log.topics[2].slice(-40)
      );

      const loggedAmount = ethers.AbiCoder.defaultAbiCoder().decode(
        ["uint256"],
        log.data
      )[0];

      eventMatches =
        loggedFrom.toLowerCase() === SENDER.toLowerCase() &&
        loggedTo.toLowerCase() === RECEIVER.toLowerCase() &&
        loggedAmount === AMOUNT;
    }
  }

  // 11. Verify expected changes
  const senderCorrect =
    senderAfter === senderBefore - AMOUNT;

  const receiverCorrect =
    receiverAfter === receiverBefore + AMOUNT;

  const supplyUnchanged =
    supplyAfter === supplyBefore;

  // 12. Display results
  console.log("\n--- SIMULATED AFTER BALANCES ---");

  console.log(
    "Sender:",
    ethers.formatUnits(senderAfter, 6),
    "USDC"
  );

  console.log(
    "Receiver:",
    ethers.formatUnits(receiverAfter, 6),
    "USDC"
  );

  console.log("\n--- VERIFICATION ---");

  console.log("Transfer succeeded:", calls[0].status === "0x1");

  console.log("Correct Transfer event:", eventMatches);

  console.log("Sender lost exactly 10 USDC:", senderCorrect);

  console.log("Receiver gained exactly 10 USDC:", receiverCorrect);

  console.log("Total supply unchanged:", supplyUnchanged);

  console.log("No unexpected logs:", allLogs.length === 1);

  // Final result
  const passed =
    senderCorrect &&
    receiverCorrect &&
    supplyUnchanged &&
    eventMatches &&
    allLogs.length === 1;

  console.log("\n==============================");

  console.log(
    "FINAL RESULT:",
    passed ? "ALL CHECKS PASSED" : "CHECKS FAILED"
  );

  console.log("==============================");

  console.log("\nPublic Sepolia was not modified.");
}

// Run program
main().catch(error => {
  console.error("\nERROR:", error.message);
});
