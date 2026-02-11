// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { WebAuthnValidator } from "src/WebAuthnValidator/WebAuthnValidator.sol";
import { WebAuthnValidatorV2 } from "src/WebAuthnValidator/WebAuthnValidatorV2.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";
import { LibSort } from "solady/utils/LibSort.sol";

/// @title Gas comparison: WebAuthnValidator v1 vs v2 (single signer, single chain)
contract GasComparisonTest is BaseTest {
    using LibSort for bytes32[];

    WebAuthnValidator internal v1;
    WebAuthnValidatorV2 internal v2;

    uint256 _pubKeyX =
        66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805;
    uint256 _pubKeyY =
        46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186;

    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    bytes constant AUTH_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001";
    uint256 constant SIG_R =
        23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880;
    uint256 constant SIG_S =
        36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088;
    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;

    function setUp() public virtual override {
        BaseTest.setUp();
        v1 = new WebAuthnValidator();
        v2 = new WebAuthnValidatorV2();

        // --- Install v1 with threshold=1, single credential ---
        WebAuthnValidator.WebAuthnCredential[] memory v1Creds =
            new WebAuthnValidator.WebAuthnCredential[](1);
        v1Creds[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: _pubKeyX,
            pubKeyY: _pubKeyY,
            requireUV: false
        });
        v1.onInstall(abi.encode(uint256(1), v1Creds));

        // --- Install v2 with single credential ---
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        WebAuthnValidatorV2.WebAuthnCredential[] memory v2Creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](1);
        v2Creds[0] = WebAuthnValidatorV2.WebAuthnCredential({
            pubKeyX: _pubKeyX,
            pubKeyY: _pubKeyY
        });
        bool[] memory requireUVs = new bool[](1);
        requireUVs[0] = false;
        v2.onInstall(abi.encode(keyIds, v2Creds, requireUVs, address(0)));
    }

    /// @dev Compute calldata gas cost: 16 per non-zero byte, 4 per zero byte
    function _calldataGas(bytes memory data) internal pure returns (uint256 gas) {
        for (uint256 i; i < data.length; ++i) {
            gas += data[i] == 0 ? 4 : 16;
        }
    }

    function _buildClientDataJSON(bytes32 challengeHash) internal pure returns (string memory) {
        bytes memory challenge = abi.encode(challengeHash);
        return string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(challenge),
            '","origin":"http://localhost:8080","crossOrigin":false}'
        );
    }

    /*//////////////////////////////////////////////////////////////////////////
                              V1 — validateUserOp (threshold=1, 1 signer)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V1_validateUserOp_singleSigner() public {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        // v1 sig format: abi.encode(bytes32[] credIds, bool usePrecompile, WebAuthn.WebAuthnAuth[] sigs)
        bytes32[] memory credIds = new bytes32[](1);
        credIds[0] = v1.generateCredentialId(_pubKeyX, _pubKeyY);

        WebAuthn.WebAuthnAuth[] memory auths = new WebAuthn.WebAuthnAuth[](1);
        auths[0] = WebAuthn.WebAuthnAuth({
            authenticatorData: AUTH_DATA,
            clientDataJSON: _buildClientDataJSON(TEST_DIGEST),
            challengeIndex: CHALLENGE_INDEX,
            typeIndex: TYPE_INDEX,
            r: SIG_R,
            s: SIG_S
        });

        userOp.signature = abi.encode(credIds, false, auths);

        uint256 gasBefore = gasleft();
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(
            v1.validateUserOp(userOp, TEST_DIGEST)
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, 0, "V1 should succeed");
        emit log_named_uint("V1 validateUserOp exec gas", gasUsed);
        emit log_named_uint("V1 sig calldata gas", _calldataGas(userOp.signature));
        emit log_named_uint("V1 total calldata gas", _calldataGas(abi.encodeCall(v1.validateUserOp, (userOp, TEST_DIGEST))));
        emit log_named_uint("V1 signature bytes", userOp.signature.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              V2 — validateUserOp (regular signing, 1 signer)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V2_validateUserOp_regularSigning() public {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);

        // v2 packed sig: [proofLength=0][keyId][requireUV][usePrecompile][packed WebAuthnAuth]
        userOp.signature = abi.encodePacked(
            uint8(0),   // proofLength = 0
            uint16(0),  // keyId
            uint8(0),   // requireUV
            uint8(0),   // usePrecompile
            SIG_R,
            SIG_S,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(AUTH_DATA.length),
            AUTH_DATA,
            clientDataJSON
        );

        uint256 gasBefore = gasleft();
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(
            v2.validateUserOp(userOp, TEST_DIGEST)
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, 0, "V2 should succeed");
        emit log_named_uint("V2 validateUserOp exec gas", gasUsed);
        emit log_named_uint("V2 sig calldata gas", _calldataGas(userOp.signature));
        emit log_named_uint("V2 total calldata gas", _calldataGas(abi.encodeCall(v2.validateUserOp, (userOp, TEST_DIGEST))));
        emit log_named_uint("V2 signature bytes", userOp.signature.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              V1 — isValidSignatureWithSender (1 signer)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V1_isValidSignatureWithSender() public {
        bytes32[] memory credIds = new bytes32[](1);
        credIds[0] = v1.generateCredentialId(_pubKeyX, _pubKeyY);

        WebAuthn.WebAuthnAuth[] memory auths = new WebAuthn.WebAuthnAuth[](1);
        auths[0] = WebAuthn.WebAuthnAuth({
            authenticatorData: AUTH_DATA,
            clientDataJSON: _buildClientDataJSON(TEST_DIGEST),
            challengeIndex: CHALLENGE_INDEX,
            typeIndex: TYPE_INDEX,
            r: SIG_R,
            s: SIG_S
        });

        bytes memory sig = abi.encode(credIds, false, auths);

        uint256 gasBefore = gasleft();
        bytes4 result = v1.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0x1626ba7e), "V1 EIP-1271 should succeed");
        emit log_named_uint("V1 1271 exec gas", gasUsed);
        emit log_named_uint("V1 1271 sig calldata gas", _calldataGas(sig));
        emit log_named_uint("V1 1271 total calldata gas", _calldataGas(abi.encodeCall(v1.isValidSignatureWithSender, (address(this), TEST_DIGEST, sig))));
        emit log_named_uint("V1 signature bytes", sig.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              V2 — isValidSignatureWithSender (1 signer)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V2_isValidSignatureWithSender() public {
        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);

        bytes memory sig = abi.encodePacked(
            uint8(0),
            uint16(0),
            uint8(0),
            uint8(0),
            SIG_R,
            SIG_S,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(AUTH_DATA.length),
            AUTH_DATA,
            clientDataJSON
        );

        uint256 gasBefore = gasleft();
        bytes4 result = v2.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0x1626ba7e), "V2 EIP-1271 should succeed");
        emit log_named_uint("V2 1271 exec gas", gasUsed);
        emit log_named_uint("V2 1271 sig calldata gas", _calldataGas(sig));
        emit log_named_uint("V2 1271 total calldata gas", _calldataGas(abi.encodeCall(v2.isValidSignatureWithSender, (address(this), TEST_DIGEST, sig))));
        emit log_named_uint("V2 signature bytes", sig.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                      V2 — validateUserOp with merkle proof (depth 1, 2-op batch)
    //////////////////////////////////////////////////////////////////////////*/

    /// @dev Helper: compute merkle root from leaf + proof (same algorithm as MerkleProofLib)
    function _computeMerkleRoot(bytes32 leaf, bytes32[] memory proof) internal pure returns (bytes32) {
        bytes32 hash = leaf;
        for (uint256 i; i < proof.length; ++i) {
            bytes32 sibling = proof[i];
            if (uint256(hash) < uint256(sibling)) {
                hash = keccak256(abi.encodePacked(hash, sibling));
            } else {
                hash = keccak256(abi.encodePacked(sibling, hash));
            }
        }
        return hash;
    }

    function _buildMerkleSignature(
        bytes32 merkleRoot,
        bytes32[] memory proof,
        string memory clientDataJSON
    )
        internal
        pure
        returns (bytes memory)
    {
        // [proofLength][merkleRoot][proof...][keyId][requireUV][usePrecompile][packedAuth]
        bytes memory sig = abi.encodePacked(
            uint8(proof.length),
            merkleRoot
        );
        for (uint256 i; i < proof.length; ++i) {
            sig = abi.encodePacked(sig, proof[i]);
        }
        sig = abi.encodePacked(
            sig,
            uint16(0),  // keyId
            uint8(0),   // requireUV
            uint8(0),   // usePrecompile
            SIG_R,
            SIG_S,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(AUTH_DATA.length),
            AUTH_DATA,
            clientDataJSON
        );
        return sig;
    }

    function test_gas_V2_validateUserOp_merkleDepth1() public {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256(abi.encode("sibling-0"));
        bytes32 merkleRoot = _computeMerkleRoot(TEST_DIGEST, proof);

        // clientDataJSON encodes merkleRoot as challenge (P-256 sig won't match, but full math runs)
        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);
        userOp.signature = _buildMerkleSignature(merkleRoot, proof, clientDataJSON);

        uint256 gasBefore = gasleft();
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(
            v2.validateUserOp(userOp, TEST_DIGEST)
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, 1, "Should fail P-256 (wrong challenge), but full execution runs");
        emit log_named_uint("V2 merkle depth=1 exec gas", gasUsed);
        emit log_named_uint("V2 merkle depth=1 calldata gas", _calldataGas(userOp.signature));
        emit log_named_uint("V2 merkle depth=1 signature bytes", userOp.signature.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                      V2 — validateUserOp with merkle proof (depth 4, 16-op batch)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V2_validateUserOp_merkleDepth4() public {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        bytes32[] memory proof = new bytes32[](4);
        for (uint256 i; i < 4; ++i) {
            proof[i] = keccak256(abi.encode("sibling", i));
        }
        bytes32 merkleRoot = _computeMerkleRoot(TEST_DIGEST, proof);

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);
        userOp.signature = _buildMerkleSignature(merkleRoot, proof, clientDataJSON);

        uint256 gasBefore = gasleft();
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(
            v2.validateUserOp(userOp, TEST_DIGEST)
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, 1, "Should fail P-256 (wrong challenge), but full execution runs");
        emit log_named_uint("V2 merkle depth=4 exec gas", gasUsed);
        emit log_named_uint("V2 merkle depth=4 calldata gas", _calldataGas(userOp.signature));
        emit log_named_uint("V2 merkle depth=4 signature bytes", userOp.signature.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                      V2 — validateUserOp with merkle proof (depth 8, 256-op batch)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V2_validateUserOp_merkleDepth8() public {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        bytes32[] memory proof = new bytes32[](8);
        for (uint256 i; i < 8; ++i) {
            proof[i] = keccak256(abi.encode("sibling", i));
        }
        bytes32 merkleRoot = _computeMerkleRoot(TEST_DIGEST, proof);

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);
        userOp.signature = _buildMerkleSignature(merkleRoot, proof, clientDataJSON);

        uint256 gasBefore = gasleft();
        uint256 result = ERC7579ValidatorBase.ValidationData.unwrap(
            v2.validateUserOp(userOp, TEST_DIGEST)
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, 1, "Should fail P-256 (wrong challenge), but full execution runs");
        emit log_named_uint("V2 merkle depth=8 exec gas", gasUsed);
        emit log_named_uint("V2 merkle depth=8 calldata gas", _calldataGas(userOp.signature));
        emit log_named_uint("V2 merkle depth=8 signature bytes", userOp.signature.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
              V2 — isValidSignatureWithSender with merkle proof (depth 1, 4, 8)
    //////////////////////////////////////////////////////////////////////////*/

    function test_gas_V2_isValidSignatureWithSender_merkleDepth1() public {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256(abi.encode("sibling-0"));
        bytes32 merkleRoot = _computeMerkleRoot(TEST_DIGEST, proof);

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);
        bytes memory sig = _buildMerkleSignature(merkleRoot, proof, clientDataJSON);

        uint256 gasBefore = gasleft();
        bytes4 result = v2.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0xffffffff), "Should fail P-256 (wrong challenge)");
        emit log_named_uint("V2 merkle depth=1 1271 exec gas", gasUsed);
        emit log_named_uint("V2 merkle depth=1 1271 calldata gas", _calldataGas(sig));
        emit log_named_uint("V2 merkle depth=1 signature bytes", sig.length);
    }

    function test_gas_V2_isValidSignatureWithSender_merkleDepth4() public {
        bytes32[] memory proof = new bytes32[](4);
        for (uint256 i; i < 4; ++i) {
            proof[i] = keccak256(abi.encode("sibling", i));
        }
        bytes32 merkleRoot = _computeMerkleRoot(TEST_DIGEST, proof);

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);
        bytes memory sig = _buildMerkleSignature(merkleRoot, proof, clientDataJSON);

        uint256 gasBefore = gasleft();
        bytes4 result = v2.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0xffffffff), "Should fail P-256 (wrong challenge)");
        emit log_named_uint("V2 merkle depth=4 1271 exec gas", gasUsed);
        emit log_named_uint("V2 merkle depth=4 1271 calldata gas", _calldataGas(sig));
        emit log_named_uint("V2 merkle depth=4 signature bytes", sig.length);
    }

    function test_gas_V2_isValidSignatureWithSender_merkleDepth8() public {
        bytes32[] memory proof = new bytes32[](8);
        for (uint256 i; i < 8; ++i) {
            proof[i] = keccak256(abi.encode("sibling", i));
        }
        bytes32 merkleRoot = _computeMerkleRoot(TEST_DIGEST, proof);

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);
        bytes memory sig = _buildMerkleSignature(merkleRoot, proof, clientDataJSON);

        uint256 gasBefore = gasleft();
        bytes4 result = v2.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, bytes4(0xffffffff), "Should fail P-256 (wrong challenge)");
        emit log_named_uint("V2 merkle depth=8 1271 exec gas", gasUsed);
        emit log_named_uint("V2 merkle depth=8 1271 calldata gas", _calldataGas(sig));
        emit log_named_uint("V2 merkle depth=8 signature bytes", sig.length);
    }
}
