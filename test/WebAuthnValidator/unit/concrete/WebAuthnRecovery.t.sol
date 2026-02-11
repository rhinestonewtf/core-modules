// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { WebAuthnValidatorV2 } from "src/WebAuthnValidator/WebAuthnValidatorV2.sol";
import { WebAuthnRecoveryBase } from "src/WebAuthnValidator/WebAuthnRecoveryBase.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

/// @dev Mock guardian that implements ERC-1271
contract MockGuardian {
    mapping(bytes32 => bool) public approvedDigests;

    function approveDigest(bytes32 digest) external {
        approvedDigests[digest] = true;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        if (approvedDigests[hash]) return 0x1626ba7e;
        return 0xffffffff;
    }
}

/// @dev Mock guardian that always rejects
contract RejectingGuardian {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}

contract WebAuthnRecoveryTest is BaseTest {
    WebAuthnValidatorV2 internal validator;
    MockGuardian internal mockGuardian;
    RejectingGuardian internal rejectingGuardian;

    // Test public keys (same as v2 test vectors)
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
        mockGuardian = new MockGuardian();
        rejectingGuardian = new RejectingGuardian();
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

    function _installData1() internal view returns (bytes memory) {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](1);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        bool[] memory requireUVs = new bool[](1);
        requireUVs[0] = false;
        return abi.encode(keyIds, creds, requireUVs, address(0));
    }

    function _install1() internal {
        validator.onInstall(_installData1());
    }

    function _newCred(
        uint16 keyId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        bool requireUV
    )
        internal
        pure
        returns (WebAuthnRecoveryBase.NewCredential memory)
    {
        return WebAuthnRecoveryBase.NewCredential({
            keyId: keyId,
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            requireUV: requireUV
        });
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN CONFIG TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_SetGuardian() public {
        validator.setGuardian(address(mockGuardian));
        assertEq(validator.guardian(address(this)), address(mockGuardian));
    }

    function test_SetGuardian_ToZero() public {
        validator.setGuardian(address(mockGuardian));
        validator.setGuardian(address(0));
        assertEq(validator.guardian(address(this)), address(0));
    }

    function test_OnInstall_SetsGuardian() public {
        uint16[] memory keyIds = new uint16[](1);
        keyIds[0] = 0;
        WebAuthnValidatorV2.WebAuthnCredential[] memory creds =
            new WebAuthnValidatorV2.WebAuthnCredential[](1);
        creds[0] = WebAuthnValidatorV2.WebAuthnCredential({ pubKeyX: _pubKeyX0, pubKeyY: _pubKeyY0 });
        bool[] memory requireUVs = new bool[](1);
        requireUVs[0] = false;
        validator.onInstall(abi.encode(keyIds, creds, requireUVs, address(mockGuardian)));

        assertEq(validator.guardian(address(this)), address(mockGuardian));
    }

    function test_OnUninstall_ClearsGuardian() public {
        _install1();
        validator.setGuardian(address(mockGuardian));
        assertEq(validator.guardian(address(this)), address(mockGuardian));

        validator.onUninstall("");
        assertEq(validator.guardian(address(this)), address(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EIP-712 DIGEST TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_GetRecoverDigest_Deterministic() public view {
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        assertEq(d1, d2, "Same inputs should produce same digest");
    }

    function test_GetRecoverDigest_DifferentNonce() public view {
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred, 1, 1000);
        assertTrue(d1 != d2, "Different nonce should produce different digest");
    }

    function test_GetRecoverDigest_DifferentExpiry() public view {
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 2000);
        assertTrue(d1 != d2, "Different expiry should produce different digest");
    }

    function test_GetRecoverDigest_DifferentKeyId() public view {
        WebAuthnRecoveryBase.NewCredential memory cred1 = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        WebAuthnRecoveryBase.NewCredential memory cred2 = _newCred(2, _pubKeyX1, _pubKeyY1, true);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred1, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), block.chainid, cred2, 0, 1000);
        assertTrue(d1 != d2, "Different keyId should produce different digest");
    }

    function test_GetRecoverDigest_DifferentAccount() public view {
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 d1 = validator.getRecoverDigest(address(this), block.chainid, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(1), block.chainid, cred, 0, 1000);
        assertTrue(d1 != d2, "Different account should produce different digest");
    }

    function test_GetRecoverDigest_DifferentChainId() public view {
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 d1 = validator.getRecoverDigest(address(this), 1, cred, 0, 1000);
        bytes32 d2 = validator.getRecoverDigest(address(this), 2, cred, 0, 1000);
        assertTrue(d1 != d2, "Different chainId should produce different digest");
    }

    function test_GetRecoverDigest_MatchesEIP712() public view {
        // Typehash now includes chainId
        bytes32 typehash = keccak256(
            "RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,uint256 newPubKeyX,uint256 newPubKeyY,bool newRequireUV,uint256 nonce,uint48 expiry)"
        );
        assertEq(typehash, validator.RECOVER_PASSKEY_TYPEHASH(), "Typehash should match");

        bytes32 structHash = keccak256(
            abi.encode(
                typehash,
                address(this),
                block.chainid, // chainId in struct
                uint256(1), // newKeyId cast to uint256
                _pubKeyX1,
                _pubKeyY1,
                true,
                uint256(42), // nonce
                uint256(uint48(9999)) // expiry cast to uint256
            )
        );

        // Sans-chainId domain separator: EIP712Domain(string name,string version,address verifyingContract)
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
                keccak256(bytes("WebAuthnValidator")),
                keccak256(bytes("2.0.0")),
                address(validator)
            )
        );

        // EIP-712: "\x19\x01" || domainSeparator || structHash
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));

        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 actual = validator.getRecoverDigest(address(this), block.chainid, cred, 42, 9999);
        assertEq(actual, expected, "Digest should match manual EIP-712 computation");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              PASSKEY RECOVERY TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithPasskey_RevertWhen_Expired() public {
        _install1();

        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        vm.warp(2000);
        vm.expectRevert(WebAuthnRecoveryBase.RecoveryExpired.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred, 0, 1000, "");
    }

    function test_RecoverWithPasskey_RevertWhen_NonceAlreadyUsed() public {
        _install1();

        // Mark nonce 42 as used by doing a guardian recovery first
        validator.setGuardian(address(mockGuardian));
        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(5, _pubKeyX1, _pubKeyY1, true);
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 42, expiry);
        mockGuardian.approveDigest(digest);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 42, expiry, "");

        // Now try to use nonce 42 again with passkey recovery
        WebAuthnRecoveryBase.NewCredential memory cred2 = _newCred(6, _pubKeyX1, _pubKeyY1, false);
        vm.expectRevert(WebAuthnRecoveryBase.NonceAlreadyUsed.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred2, 42, expiry, "");
    }

    function test_RecoverWithPasskey_RevertWhen_InvalidSignature() public {
        _install1();

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        // Sign over wrong digest (TEST_DIGEST, not recovery digest)
        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);

        vm.expectRevert(WebAuthnRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred, 0, expiry, sig);
    }

    function test_RecoverWithPasskey_RevertWhen_NotInitialized() public {
        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        // _validateSignatureWithConfig returns false for uninitialized
        vm.expectRevert(WebAuthnRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(
            address(this), block.chainid, cred, 0, expiry,
            _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, _buildClientDataJSON(TEST_DIGEST))
        );
    }

    function test_RecoverWithPasskey_RevertWhen_ZeroPubKey() public {
        _install1();

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, 0, 0, false);
        string memory clientDataJSON = _buildClientDataJSON(TEST_DIGEST);
        bytes memory sig = _buildRegularSignature(0, 0, 0, SIG_R, SIG_S, AUTH_DATA, clientDataJSON);
        vm.expectRevert(WebAuthnRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(address(this), block.chainid, cred, 0, expiry, sig);
    }

    function test_RecoverWithPasskey_RevertWhen_InvalidChainId() public {
        _install1();

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        vm.expectRevert(WebAuthnRecoveryBase.InvalidChainId.selector);
        validator.recoverWithPasskey(address(this), 999, cred, 0, expiry, "");
    }

    function test_RecoverWithPasskey_ChainIdZero_AnyChain() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        // chainId=0 means any chain — should not revert with InvalidChainId
        // (will revert with InvalidRecoverySignature since sig is empty, which proves chainId check passed)
        vm.expectRevert(WebAuthnRecoveryBase.InvalidRecoverySignature.selector);
        validator.recoverWithPasskey(address(this), 0, cred, 0, expiry, "");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              GUARDIAN RECOVERY TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_Success() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        // Verify credential was added
        (uint256 px, uint256 py) = validator.getCredential(1, true, address(this));
        assertEq(px, _pubKeyX1, "New credential pubKeyX should be set");
        assertEq(py, _pubKeyY1, "New credential pubKeyY should be set");
        assertEq(validator.credentialCount(address(this)), 2, "Should now have 2 credentials");
    }

    function test_RecoverWithGuardian_NonceMarkedUsed() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 7;
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        assertFalse(validator.nonceUsed(address(this), nonce), "Nonce should not be used initially");

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        assertTrue(validator.nonceUsed(address(this), nonce), "Nonce should be marked as used");
    }

    function test_RecoverWithGuardian_RevertWhen_Expired() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        vm.warp(2000);
        vm.expectRevert(WebAuthnRecoveryBase.RecoveryExpired.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, 1000, "");
    }

    function test_RecoverWithGuardian_RevertWhen_NonceAlreadyUsed() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 0;
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        // First recovery succeeds
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);
        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");

        // Second recovery with same nonce fails
        WebAuthnRecoveryBase.NewCredential memory cred2 = _newCred(2, _pubKeyX1, _pubKeyY1, false);
        vm.expectRevert(WebAuthnRecoveryBase.NonceAlreadyUsed.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred2, nonce, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_GuardianNotConfigured() public {
        _install1();
        // No guardian set

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        vm.expectRevert(WebAuthnRecoveryBase.GuardianNotConfigured.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_InvalidGuardianSignature() public {
        _install1();
        validator.setGuardian(address(rejectingGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        vm.expectRevert(WebAuthnRecoveryBase.InvalidGuardianSignature.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_ZeroPubKey() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, 0, 0, false);
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectRevert(WebAuthnValidatorV2.InvalidPublicKey.selector);
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_DuplicateCredKey() public {
        _install1(); // keyId 0, requireUV=false
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(0, _pubKeyX1, _pubKeyY1, false);
        // Try to add keyId 0, requireUV=false again (duplicate credKey)
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectRevert(abi.encodeWithSelector(WebAuthnValidatorV2.KeyIdAlreadyExists.selector, 0));
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_NotInitialized() public {
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        // _addCredentialRecovery checks isInitialized
        vm.expectRevert();
        validator.recoverWithGuardian(address(this), block.chainid, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_RevertWhen_InvalidChainId() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        vm.expectRevert(WebAuthnRecoveryBase.InvalidChainId.selector);
        validator.recoverWithGuardian(address(this), 999, cred, 0, expiry, "");
    }

    function test_RecoverWithGuardian_ChainIdZero_AnyChain() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        // chainId=0 means any chain
        bytes32 digest = validator.getRecoverDigest(address(this), 0, cred, 0, expiry);
        mockGuardian.approveDigest(digest);

        validator.recoverWithGuardian(address(this), 0, cred, 0, expiry, "");

        // Verify credential was added
        (uint256 px, uint256 py) = validator.getCredential(1, true, address(this));
        assertEq(px, _pubKeyX1);
        assertEq(py, _pubKeyY1);
    }

    function test_RecoverWithGuardian_MultipleDifferentNonces() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);

        // Recovery with nonce 10
        WebAuthnRecoveryBase.NewCredential memory cred1 = _newCred(1, _pubKeyX1, _pubKeyY1, true);
        bytes32 digest1 = validator.getRecoverDigest(address(this), block.chainid, cred1, 10, expiry);
        mockGuardian.approveDigest(digest1);
        validator.recoverWithGuardian(address(this), block.chainid, cred1, 10, expiry, "");

        // Recovery with nonce 20 (different keyId)
        WebAuthnRecoveryBase.NewCredential memory cred2 = _newCred(2, _pubKeyX1, _pubKeyY1, false);
        bytes32 digest2 = validator.getRecoverDigest(address(this), block.chainid, cred2, 20, expiry);
        mockGuardian.approveDigest(digest2);
        validator.recoverWithGuardian(address(this), block.chainid, cred2, 20, expiry, "");

        // Both nonces used
        assertTrue(validator.nonceUsed(address(this), 10));
        assertTrue(validator.nonceUsed(address(this), 20));
        assertFalse(validator.nonceUsed(address(this), 15)); // unused nonce

        // 3 credentials total now (original + 2 recovered)
        assertEq(validator.credentialCount(address(this)), 3);
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EVENT TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_RecoverWithGuardian_EmitsEvent() public {
        _install1();
        validator.setGuardian(address(mockGuardian));

        uint48 expiry = uint48(block.timestamp + 1000);
        uint256 nonce = 5;
        WebAuthnRecoveryBase.NewCredential memory cred = _newCred(1, _pubKeyX1, _pubKeyY1, true);

        bytes32 digest = validator.getRecoverDigest(address(this), block.chainid, cred, nonce, expiry);
        mockGuardian.approveDigest(digest);

        vm.expectEmit(true, true, true, true);
        emit WebAuthnRecoveryBase.GuardianRecoveryExecuted(
            address(this), address(mockGuardian), 1, nonce
        );

        validator.recoverWithGuardian(address(this), block.chainid, cred, nonce, expiry, "");
    }

    function test_SetGuardian_EmitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit WebAuthnRecoveryBase.GuardianSet(address(this), address(mockGuardian));

        validator.setGuardian(address(mockGuardian));
    }
}
