// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";
import { WebAuthnValidatorV2 } from "src/WebAuthnValidator/WebAuthnValidatorV2.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

/// @notice Compute the EIP-712 wrapped challenge values for regenerating test vectors
/// @dev Run: forge script script/ComputeTestChallenge.s.sol -vvv
contract ComputeTestChallenge is Script {
    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    bytes constant AUTH_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001";

    function run() public {
        WebAuthnValidatorV2 validator = new WebAuthnValidatorV2();

        console2.log("=== WebAuthnValidatorV2 Test Challenge Computation ===");
        console2.log("");
        console2.log("Validator address:", address(validator));
        console2.log("Chain ID:", block.chainid);
        console2.log("");

        // PasskeyDigest (regular signing, chain-specific)
        bytes32 passkeyDigest = validator.getPasskeyDigest(TEST_DIGEST);
        console2.log("--- PasskeyDigest (regular signing) ---");
        console2.log("Input TEST_DIGEST:");
        console2.logBytes32(TEST_DIGEST);
        console2.log("EIP-712 wrapped challenge (PasskeyDigest):");
        console2.logBytes32(passkeyDigest);

        // Build clientDataJSON for regular signing
        bytes memory challengeBytes = abi.encode(passkeyDigest);
        string memory clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(challengeBytes),
            '","origin":"http://localhost:8080","crossOrigin":false}'
        );
        console2.log("");
        console2.log("clientDataJSON for regular signing:");
        console2.log(clientDataJSON);

        // The P-256 key signs: sha256(authData || sha256(clientDataJSON))
        bytes32 clientDataHash = sha256(bytes(clientDataJSON));
        bytes32 signedMessage = sha256(abi.encodePacked(AUTH_DATA, clientDataHash));
        console2.log("");
        console2.log("sha256(clientDataJSON):");
        console2.logBytes32(clientDataHash);
        console2.log("P-256 signs sha256(authData || sha256(clientDataJSON)):");
        console2.logBytes32(signedMessage);

        // PasskeyMultichain (merkle signing, chain-agnostic)
        console2.log("");
        console2.log("--- PasskeyMultichain (merkle signing) ---");
        bytes32 multichainDigest = validator.getPasskeyMultichain(TEST_DIGEST);
        console2.log("EIP-712 wrapped challenge (PasskeyMultichain):");
        console2.logBytes32(multichainDigest);
    }
}
