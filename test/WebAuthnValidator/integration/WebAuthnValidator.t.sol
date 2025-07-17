// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseIntegrationTest, ModuleKitHelpers } from "test/BaseIntegration.t.sol";
import { WebAuthnValidator } from "src/WebAuthnValidator/WebAuthnValidator.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { MODULE_TYPE_VALIDATOR } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { UserOpData } from "modulekit/ModuleKit.sol";
import { IERC1271 } from "modulekit/Interfaces.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

contract WebAuthnValidatorIntegrationTest is BaseIntegrationTest {
    using ModuleKitHelpers for *;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    WebAuthnValidator internal validator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    uint256 _threshold = 2;

    // Test public keys for WebAuthn credentials
    uint256[] _pubKeysX;
    uint256[] _pubKeysY;
    bool[] _requireUVs;

    // Mock WebAuthn signature data
    WebAuthn.WebAuthnAuth mockAuth1;
    WebAuthn.WebAuthnAuth mockAuth2;

    // Generated credential IDs
    bytes32[] _credentialIds;

    // Mock signature data for testing
    bytes sig;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        validator = new WebAuthnValidator();

        // Initialize credential arrays
        _pubKeysX = new uint256[](2);
        _pubKeysY = new uint256[](2);
        _requireUVs = new bool[](2);

        // Use real public keys
        _pubKeysX[0] =
            66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805;
        _pubKeysY[0] =
            46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186;
        _requireUVs[0] = false;

        _pubKeysX[1] =
            77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311;
        _pubKeysY[1] =
            20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644;
        _requireUVs[1] = true;

        // Pre-compute credential IDs for testing
        _credentialIds = new bytes32[](2);
        for (uint256 i = 0; i < 2; i++) {
            _credentialIds[i] = validator.generateCredentialId(
                _pubKeysX[i], _pubKeysY[i], address(instance.account)
            );
        }

        // Use a fixed challenge for testing
        bytes memory challenge =
            abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Set up real WebAuthn authentication data for first credential
        mockAuth1 = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                '","origin":"http://localhost:8080","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880,
            s: 36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088
        });

        // Set up real WebAuthn authentication data for second credential
        mockAuth2 = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                '","origin":"http://localhost:8080","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 70_190_788_404_940_879_339_470_429_048_068_864_326_256_942_039_718_306_809_827_270_917_601_845_266_065,
            s: 372_310_544_955_428_259_193_186_543_685_199_264_627_091_796_694_315_697_785_543_526_117_532_572_367
        });

        // Create signature data for testing
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        sigs[0] = mockAuth1;
        sigs[1] = mockAuth2;

        // Encode the signatures
        sig = abi.encode(_credentialIds, false, sigs);

        // Setup WebAuthCredential data
        WebAuthnValidator.WebAuthnCredential[] memory credentialData =
            new WebAuthnValidator.WebAuthnCredential[](2);
        credentialData[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: _pubKeysX[0],
            pubKeyY: _pubKeysY[0],
            requireUV: _requireUVs[0]
        });
        credentialData[1] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: _pubKeysX[1],
            pubKeyY: _pubKeysY[1],
            requireUV: _requireUVs[1]
        });

        // Install the validator module on the account
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: abi.encode(_threshold, credentialData)
        });
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstallSetCredentialsAndThreshold() public view {
        // It should set the credentials, threshold and credential count
        uint256 threshold = validator.threshold(address(instance.account));
        assertEq(threshold, _threshold, "Threshold should be set correctly");

        bytes32[] memory credIds = validator.getCredentialIds(address(instance.account));
        assertEq(credIds.length, _pubKeysX.length, "Credential count should match");

        // Verify the credential IDs match what we expect (may be in different order due to set
        // storage)
        bool foundCred0 = false;
        bool foundCred1 = false;

        for (uint256 i = 0; i < credIds.length; i++) {
            if (credIds[i] == _credentialIds[0]) foundCred0 = true;
            if (credIds[i] == _credentialIds[1]) foundCred1 = true;
        }

        assertTrue(foundCred0, "First credential should be found");
        assertTrue(foundCred1, "Second credential should be found");

        uint256 credentialCount = validator.getCredentialCount(address(instance.account));
        assertEq(credentialCount, _pubKeysX.length, "Credential count should match");
    }

    function test_OnUninstallRemovesCredentialsAndThreshold() public {
        // It should remove the credentials and threshold
        instance.uninstallModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: ""
        });

        uint256 threshold = validator.threshold(address(instance.account));
        assertEq(threshold, 0, "Threshold should be reset to 0");

        bytes32[] memory credentialIds = validator.getCredentialIds(address(instance.account));
        assertEq(credentialIds.length, 0, "All credentials should be removed");

        uint256 credentialCount = validator.getCredentialCount(address(instance.account));
        assertEq(credentialCount, 0, "Credential count should be reset to 0");
    }

    function test_SetThreshold() public {
        // It should set the threshold
        uint256 newThreshold = 1;

        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(WebAuthnValidator.setThreshold.selector, newThreshold),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        uint256 threshold = validator.threshold(address(instance.account));
        assertEq(threshold, newThreshold, "Threshold should be updated");
    }

    function test_SetThreshold_RevertWhen_ThresholdTooHigh() public {
        // It should revert when threshold is too high
        uint256 newThreshold = 3;

        instance.expect4337Revert();
        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(WebAuthnValidator.setThreshold.selector, newThreshold),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();
    }

    function test_AddCredential() public {
        // It should add a credential
        // It should increment the credential count
        uint256 newPubKeyX = 99_999;
        uint256 newPubKeyY = 88_888;
        bool newRequireUV = true;

        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(
                WebAuthnValidator.addCredential.selector, newPubKeyX, newPubKeyY, newRequireUV
            ),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        // Check credential was added
        bytes32 newCredentialId =
            validator.generateCredentialId(newPubKeyX, newPubKeyY, address(instance.account));

        assertTrue(
            validator.hasCredentialById(newCredentialId, address(instance.account)),
            "New credential should exist"
        );

        // Check credential count
        uint256 credentialCount = validator.getCredentialCount(address(instance.account));
        assertEq(credentialCount, _pubKeysX.length + 1, "Credential count should be incremented");
    }

    function test_RemoveCredential() public {
        // First lower the threshold so we can remove a credential
        test_SetThreshold();

        // It should remove a credential and decrement the credential count
        instance.getExecOps({
            target: address(validator),
            value: 0,
            callData: abi.encodeWithSelector(
                WebAuthnValidator.removeCredential.selector, _pubKeysX[0], _pubKeysY[0], _requireUVs[0]
            ),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        // Check credential was removed
        assertFalse(
            validator.hasCredentialById(_credentialIds[0], address(instance.account)),
            "Credential should be removed"
        );

        // Check credential count
        uint256 credentialCount = validator.getCredentialCount(address(instance.account));
        assertEq(credentialCount, _pubKeysX.length - 1, "Credential count should be decremented");
    }

    function test_ERC1271_goated() public {
        // It should return the magic value for valid WebAuthn signatures
        bytes32 hash = bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
        // Change the order of sigs
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        sigs[1] = mockAuth2;
        sigs[0] = mockAuth1;
        sig = abi.encode(_credentialIds, false, sigs);
        bool isValid = instance.isValidSignature(address(validator), hash, sig);
        assertTrue(isValid, "ERC1271 signature validation should pass");
    }

    function test_ValidateSignatureWithData() public view {
        // It should validate standalone signature data
        bytes32 hash = bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Prepare credential arrays for stateless validation
        bytes32[] memory credentialIds = new bytes32[](2);
        credentialIds[0] = _credentialIds[0];
        credentialIds[1] = _credentialIds[1];

        WebAuthnValidator.WebAuthnCredential[] memory credentialData =
            new WebAuthnValidator.WebAuthnCredential[](2);
        credentialData[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: _pubKeysX[0],
            pubKeyY: _pubKeysY[0],
            requireUV: _requireUVs[0]
        });
        credentialData[1] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: _pubKeysX[1],
            pubKeyY: _pubKeysY[1],
            requireUV: _requireUVs[1]
        });

        // Create verification context
        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 2,
            credentialIds: credentialIds,
            credentialData: credentialData
        });

        bytes memory data = abi.encode(context, address(instance.account));
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        (credentialIds,, sigs) = abi.decode(sig, (bytes32[], bool, WebAuthn.WebAuthnAuth[]));

        // Validate the signatures
        bool isValid = validator.validateSignatureWithData(hash, abi.encode(sigs), data);
        assertTrue(isValid, "Stateless signature validation should pass");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function createTestUserOpHash() internal pure returns (bytes32) {
        return bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
    }
}
