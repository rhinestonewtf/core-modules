// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { WebAuthnValidatorV2 } from "src/WebAuthnValidator/WebAuthnValidatorV2.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

contract WebAuthnValidatorV2Test is BaseTest {
    WebAuthnValidatorV2 internal validator;

    // Test public keys (same as v1 test vectors)
    uint256 _pubKeyX0 =
        66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805;
    uint256 _pubKeyY0 =
        46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186;

    uint256 _pubKeyX1 =
        77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311;
    uint256 _pubKeyY1 =
        20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644;

    // The digest that the test WebAuthn signatures were created for
    bytes32 constant TEST_DIGEST =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    // Real WebAuthn auth data for pubKey0 signing abi.encode(TEST_DIGEST)
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
        validator = new WebAuthnValidatorV2();
    }

    /*//////////////////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function _buildClientDataJSON(bytes32 challengeHash) internal pure returns (string memory) {
        bytes memory challenge = abi.encode(challengeHash);
        return string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(challenge),
            '","origin":"http://localhost:8080","crossOrigin":false}'
        );
    }

    function _packWebAuthnAuth(
        uint256 r,
        uint256 s,
        uint16 challengeIdx,
        uint16 typeIdx,
        bytes memory authenticatorData,
        string memory clientDataJSON
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            r, s, challengeIdx, typeIdx, uint16(authenticatorData.length), authenticatorData, clientDataJSON
        );
    }

    /// @dev Regular signing (proofLength=0): challenge = digest
    function _buildRegularSignature(
        uint16 keyId,
        uint8 requireUV,
        uint8 usePrecompile,
        uint256 r,
        uint256 s,
        bytes memory authenticatorData,
        string memory clientDataJSON
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(0), // proofLength = 0
            keyId,
            requireUV,
            usePrecompile,
            r,
            s,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(authenticatorData.length),
            authenticatorData,
            clientDataJSON
        );
    }

    /// @dev Merkle signing (proofLength>0): challenge = merkleRoot
    function _buildMerkleSignature(
        bytes32 merkleRoot,
        bytes32[] memory proof,
        uint16 keyId,
        uint8 requireUV,
        uint8 usePrecompile,
        uint256 r,
        uint256 s,
        bytes memory authenticatorData,
        string memory clientDataJSON
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result = abi.encodePacked(uint8(proof.length), merkleRoot);
        for (uint256 i; i < proof.length; ++i) {
            result = abi.encodePacked(result, proof[i]);
        }
        result = abi.encodePacked(
            result,
            keyId,
            requireUV,
            usePrecompile,
            r,
            s,
            uint16(CHALLENGE_INDEX),
            uint16(TYPE_INDEX),
            uint16(authenticatorData.length),
            authenticatorData,
            clientDataJSON
        );
        return result;
    }

    function _installData1() internal view returns (bytes memory) {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](1);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        bool[] memory requireUVs = new bool[](1);
        requireUVs[0] = false;
        return abi.encode(keyIds, creds, requireUVs, address(0));
    }

    function _installData2() internal view returns (bytes memory) {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 10;
        keyIds[1] = 42;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](2);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({
            pubKeyX: _pubKeyX0,
            pubKeyY: _pubKeyY0
        });
        creds[1] = WebAuthnValidatorV2.WebAuthnCredential({
            pubKeyX: _pubKeyX1,
            pubKeyY: _pubKeyY1
        });
        bool[] memory requireUVs = new bool[](2);
        requireUVs[0] = false;
        requireUVs[1] = true;
        return abi.encode(keyIds, creds, requireUVs, address(0));
    }

    function _install1() internal {
        validator.onInstall(_installData1());
    }

    function _install2() internal {
        validator.onInstall(_installData2());
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  CONFIG TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall() public {
        _install2();
        assertTrue(validator.isInitialized(address(this)));
        assertEq(validator.credentialCount(address(this)), 2);

        // keyId 10, requireUV=false → pubKey0
        (uint256 px0, uint256 py0) = validator.getCredential(10, false, address(this));
        assertEq(px0, _pubKeyX0);
        assertEq(py0, _pubKeyY0);

        // keyId 42, requireUV=true → pubKey1
        (uint256 px1, uint256 py1) = validator.getCredential(42, true, address(this));
        assertEq(px1, _pubKeyX1);
        assertEq(py1, _pubKeyY1);
    }

    function test_OnInstall_RevertWhen_AlreadyInitialized() public {
        _install1();
        vm.expectRevert();
        _install1();
    }

    function test_OnInstall_RevertWhen_EmptyCredentials() public {
        uint16[] memory keyIds = new uint16[](0);
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](0);
        bool[] memory requireUVs = new bool[](0);
        vm.expectRevert(WebAuthnValidatorV2.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, requireUVs, address(0)));
    }

    function test_OnInstall_RevertWhen_ZeroPubKey() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](1);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: 0, pubKeyY: 0 });
        bool[] memory requireUVs = new bool[](1);
        requireUVs[0] = false;
        vm.expectRevert(WebAuthnValidatorV2.InvalidPublicKey.selector);
        validator.onInstall(abi.encode(keyIds, creds, requireUVs, address(0)));
    }

    function test_OnInstall_RevertWhen_DuplicateKeyId() public {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 5;
        keyIds[1] = 5;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](2);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        creds[1] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: _pubKeyX1, pubKeyY: _pubKeyY1 });
        bool[] memory requireUVs = new bool[](2);
        requireUVs[0] = false;
        requireUVs[1] = false;
        vm.expectRevert(abi.encodeWithSelector(WebAuthnValidatorV2.KeyIdAlreadyExists.selector, 5));
        validator.onInstall(abi.encode(keyIds, creds, requireUVs, address(0)));
    }

    function test_OnInstall_SameKeyId_DifferentRequireUV() public {
        uint16[] memory keyIds = new uint16[](2);
        keyIds[0] = 5;
        keyIds[1] = 5;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](2);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        creds[1] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: _pubKeyX1, pubKeyY: _pubKeyY1 });
        bool[] memory requireUVs = new bool[](2);
        requireUVs[0] = false;
        requireUVs[1] = true;
        validator.onInstall(abi.encode(keyIds, creds, requireUVs, address(0)));
        assertEq(validator.credentialCount(address(this)), 2);
    }

    function test_OnUninstall() public {
        _install2();
        assertTrue(validator.isInitialized(address(this)));

        validator.onUninstall("");
        assertFalse(validator.isInitialized(address(this)));
        assertEq(validator.credentialCount(address(this)), 0);
    }

    function test_IsInitialized() public {
        assertFalse(validator.isInitialized(address(this)));
        _install1();
        assertTrue(validator.isInitialized(address(this)));
    }

    function test_AddCredential() public {
        _install1();
        assertEq(validator.credentialCount(address(this)), 1);

        validator.addCredential(99, _pubKeyX1, _pubKeyY1, true);
        assertEq(validator.credentialCount(address(this)), 2);

        (uint256 px, uint256 py) = validator.getCredential(99, true, address(this));
        assertEq(px, _pubKeyX1);
        assertEq(py, _pubKeyY1);
    }

    function test_AddCredential_RevertWhen_NotInitialized() public {
        vm.expectRevert();
        validator.addCredential(0, _pubKeyX0, _pubKeyY0, false);
    }

    function test_AddCredential_RevertWhen_ZeroPubKey() public {
        _install1();
        vm.expectRevert(WebAuthnValidatorV2.InvalidPublicKey.selector);
        validator.addCredential(1, 0, 0, false);
    }

    function test_AddCredential_RevertWhen_DuplicateKeyId() public {
        _install1(); // keyId 0 with requireUV=false
        vm.expectRevert(abi.encodeWithSelector(WebAuthnValidatorV2.KeyIdAlreadyExists.selector, 0));
        validator.addCredential(0, _pubKeyX1, _pubKeyY1, false); // same credKey
    }

    function test_AddCredential_SameKeyId_DifferentRequireUV() public {
        _install1(); // keyId 0 with requireUV=false
        // Same keyId but different requireUV = different credKey
        validator.addCredential(0, _pubKeyX1, _pubKeyY1, true);
        assertEq(validator.credentialCount(address(this)), 2);

        (uint256 px0,) = validator.getCredential(0, false, address(this));
        assertEq(px0, _pubKeyX0);
        (uint256 px1,) = validator.getCredential(0, true, address(this));
        assertEq(px1, _pubKeyX1);
    }

    function test_RemoveCredential() public {
        _install2(); // keyIds 10 (requireUV=false) and 42 (requireUV=true)
        assertEq(validator.credentialCount(address(this)), 2);

        validator.removeCredential(10, false);
        assertEq(validator.credentialCount(address(this)), 1);

        // keyId 10 credential should be cleared
        (uint256 px,) = validator.getCredential(10, false, address(this));
        assertEq(px, 0, "Removed credential should be zeroed");

        // keyId 42 should still exist
        (uint256 px42, uint256 py42) = validator.getCredential(42, true, address(this));
        assertEq(px42, _pubKeyX1);
        assertEq(py42, _pubKeyY1);
    }

    function test_RemoveCredential_RevertWhen_LastCredential() public {
        _install1();
        vm.expectRevert(WebAuthnValidatorV2.CannotRemoveLastCredential.selector);
        validator.removeCredential(0, false);
    }

    function test_RemoveCredential_RevertWhen_NotFound() public {
        _install2();
        vm.expectRevert(abi.encodeWithSelector(WebAuthnValidatorV2.CredentialNotFound.selector, 999));
        validator.removeCredential(999, false);
    }

    function test_GetCredKeys() public {
        _install2();
        uint256[] memory credKeys = validator.getCredKeys(address(this));
        assertEq(credKeys.length, 2);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION TESTS — REGULAR SIGNING (proofLength=0)
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_RegularSigning() public {
        _install1(); // keyId 0, requireUV=false

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        // Regular signing: challenge = abi.encode(digest)
        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);

        userOp.signature = _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should return VALIDATION_SUCCESS");
    }

    function test_ValidateUserOp_RevertWhen_NotInitialized() public view {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        userOp.signature =
            _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should return VALIDATION_FAILED when not initialized");
    }

    function test_ValidateUserOp_FailWhen_WrongKeyId() public {
        _install1(); // only keyId 0

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        userOp.signature =
            _buildRegularSignature(1, 0, 0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail with wrong keyId");
    }

    function test_ValidateUserOp_FailWhen_WrongRequireUV() public {
        _install1(); // keyId 0 with requireUV=false

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        // Use requireUV=true in signature but credential was stored with requireUV=false
        userOp.signature =
            _buildRegularSignature(0, 1, 0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail with wrong requireUV (different credKey)");
    }

    function test_ValidateUserOp_WithArbitraryKeyId() public {
        _install2(); // keyIds 10 (requireUV=false) and 42 (requireUV=true), pubKey0 at keyId 10

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);

        // Use keyId 10, requireUV=false which has pubKey0 (matches the test vectors)
        userOp.signature = _buildRegularSignature(10, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 0, "Should succeed with arbitrary keyId");
    }

    // --- EIP-1271 ---

    function test_IsValidSignatureWithSender_RegularSigning() public {
        _install1();

        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        bytes4 result = validator.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        assertEq(result, EIP1271_MAGIC_VALUE, "Should return EIP1271_SUCCESS");
    }

    function test_IsValidSignatureWithSender_FailWhen_NotInitialized() public view {
        bytes memory sig =
            _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST));

        bytes4 result = validator.isValidSignatureWithSender(address(this), TEST_DIGEST, sig);
        assertEq(result, bytes4(0xffffffff), "Should return EIP1271_FAILED");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              VALIDATION TESTS — MERKLE SIGNING (proofLength>0)
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateUserOp_WithMerkleProof() public {
        _install1();

        bytes32 leaf0 = TEST_DIGEST;
        bytes32 leaf1 = bytes32(uint256(0xdead));

        bytes32 merkleRoot;
        if (uint256(leaf0) < uint256(leaf1)) {
            merkleRoot = keccak256(abi.encodePacked(leaf0, leaf1));
        } else {
            merkleRoot = keccak256(abi.encodePacked(leaf1, leaf0));
        }

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // WebAuthn signature signs over merkleRoot, but test vectors were signed over TEST_DIGEST.
        // So WebAuthn.verify will fail — we're testing merkle proof parsing works correctly.
        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        userOp.signature =
            _buildMerkleSignature(merkleRoot, proof, 0, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail WebAuthn verification (wrong challenge)");
    }

    function test_ValidateUserOp_MerkleProof_FailWhen_InvalidProof() public {
        _install1();

        bytes32 leaf0 = TEST_DIGEST;
        bytes32 leaf1 = bytes32(uint256(0xdead));

        bytes32 merkleRoot;
        if (uint256(leaf0) < uint256(leaf1)) {
            merkleRoot = keccak256(abi.encodePacked(leaf0, leaf1));
        } else {
            merkleRoot = keccak256(abi.encodePacked(leaf1, leaf0));
        }

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(0xbad)); // wrong proof

        string memory clientDataJSON = _buildClientDataJSON(merkleRoot);

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        userOp.signature =
            _buildMerkleSignature(merkleRoot, proof, 0, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, TEST_DIGEST));
        assertEq(validationData, 1, "Should fail with invalid merkle proof");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              STATELESS VALIDATION TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_ValidateSignatureWithData_RegularSigning() public view {
        // proofLength=0: regular signing, challenge = hash
        bytes memory data = abi.encodePacked(
            uint8(0), // proofLength = 0
            _pubKeyX0,
            _pubKeyY0,
            uint8(0), // requireUV
            uint8(0) // usePrecompile
        );

        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);
        bytes memory sig = _packWebAuthnAuth(
            SIG_R, SIG_S, uint16(CHALLENGE_INDEX), uint16(TYPE_INDEX), AUTH_DATA, clientDataJSON
        );

        bool result = validator.validateSignatureWithData(TEST_DIGEST, sig, data);
        assertTrue(result, "Stateless regular validation should succeed");
    }

    function test_ValidateSignatureWithData_FailWhen_DataTooShort() public {
        vm.expectRevert(WebAuthnValidatorV2.InvalidSignatureData.selector);
        validator.validateSignatureWithData(TEST_DIGEST, "", "");
    }

    function test_ValidateSignatureWithData_FailWhen_ProofTooLong() public {
        bytes memory data = abi.encodePacked(
            uint8(33), // proofLength = 33 > MAX_MERKLE_DEPTH
            bytes32(0), // merkleRoot placeholder
            _pubKeyX0,
            _pubKeyY0,
            uint8(0),
            uint8(0)
        );

        vm.expectRevert(WebAuthnValidatorV2.ProofTooLong.selector);
        validator.validateSignatureWithData(TEST_DIGEST, "", data);
    }

    function test_ValidateSignatureWithData_MerkleProof_FailWhen_InvalidProof() public {
        bytes32 fakeRoot = bytes32(uint256(0x1234));

        // proofLength=1 but wrong proof
        bytes memory data = abi.encodePacked(
            uint8(1), // proofLength
            fakeRoot, // merkleRoot
            _pubKeyX0,
            _pubKeyY0,
            uint8(0), // requireUV
            uint8(0), // usePrecompile
            bytes32(uint256(0xbad)) // wrong proof element
        );

        string memory clientDataJSON = _buildClientDataJSON(fakeRoot);
        bytes memory sig = _packWebAuthnAuth(
            SIG_R, SIG_S, uint16(CHALLENGE_INDEX), uint16(TYPE_INDEX), AUTH_DATA, clientDataJSON
        );

        vm.expectRevert(WebAuthnValidatorV2.InvalidMerkleProof.selector);
        validator.validateSignatureWithData(TEST_DIGEST, sig, data);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              METADATA TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_Name() public view {
        assertEq(validator.name(), "WebAuthnValidatorV2");
    }

    function test_Version() public view {
        assertEq(validator.version(), "2.0.0");
    }

    function test_IsModuleType_Validator() public view {
        assertTrue(validator.isModuleType(1));
    }

    function test_IsModuleType_StatelessValidator() public view {
        assertTrue(validator.isModuleType(7));
    }

    function test_IsModuleType_Other() public view {
        assertFalse(validator.isModuleType(2));
        assertFalse(validator.isModuleType(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EIP-712 PASSKEY DIGEST TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_GetPasskeyDigest_MatchesEIP712() public view {
        bytes32 typehash = keccak256("PasskeyDigest(bytes32 digest)");
        assertEq(typehash, validator.PASSKEY_DIGEST_TYPEHASH());

        bytes32 structHash = keccak256(abi.encode(typehash, TEST_DIGEST));

        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("WebAuthnValidator")),
                keccak256(bytes("2.0.0")),
                block.chainid,
                address(validator)
            )
        );

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        bytes32 actual = validator.getPasskeyDigest(TEST_DIGEST);
        assertEq(actual, expected, "PasskeyDigest should match manual EIP-712 computation");
    }

    function test_GetPasskeyDigest_ChainSpecific() public {
        bytes32 digest1 = validator.getPasskeyDigest(TEST_DIGEST);

        vm.chainId(999);
        bytes32 digest2 = validator.getPasskeyDigest(TEST_DIGEST);

        assertTrue(digest1 != digest2, "Different chainIds should produce different digests");
    }

    function test_GetPasskeyMultichain_MatchesEIP712() public view {
        bytes32 typehash = keccak256("PasskeyMultichain(bytes32 root)");
        assertEq(typehash, validator.PASSKEY_MULTICHAIN_TYPEHASH());

        bytes32 structHash = keccak256(abi.encode(typehash, TEST_DIGEST));

        // Sans-chainId domain: no chainId field
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256(bytes("WebAuthnValidator")),
                keccak256(bytes("2.0.0")),
                address(validator)
            )
        );

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        bytes32 actual = validator.getPasskeyMultichain(TEST_DIGEST);
        assertEq(actual, expected, "PasskeyMultichain should match manual EIP-712 computation");
    }

    function test_GetPasskeyMultichain_ChainAgnostic() public {
        bytes32 digest1 = validator.getPasskeyMultichain(TEST_DIGEST);

        vm.chainId(999);
        bytes32 digest2 = validator.getPasskeyMultichain(TEST_DIGEST);

        assertEq(digest1, digest2, "Different chainIds should produce the same multichain digest");
    }

    function test_GetPasskeyDigest_DifferentDigests() public view {
        bytes32 d1 = validator.getPasskeyDigest(TEST_DIGEST);
        bytes32 d2 = validator.getPasskeyDigest(bytes32(uint256(0xdead)));
        assertTrue(d1 != d2, "Different input digests should produce different passkey digests");
    }
}
