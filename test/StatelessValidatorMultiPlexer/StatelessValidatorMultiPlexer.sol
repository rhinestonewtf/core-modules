// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { StatelessValidatorMultiPlexer } from
    "src/StatelessValidatorMultiPlexer/StatelessValidatorMultiPlexer.sol";
import { OwnableValidator } from "src/OwnableValidator/OwnableValidator.sol";
import { WebAuthnValidator } from "src/WebAuthnValidator/WebAuthnValidator.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { signHash } from "test/utils/Signature.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";
import { LibSort } from "solady/utils/LibSort.sol";

contract StatelessValidatorMultiPlexerTest is BaseTest {
    using LibSort for *;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    StatelessValidatorMultiPlexer internal multiplexer;
    OwnableValidator internal ownableValidator;
    WebAuthnValidator internal webAuthnValidator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    uint256 ownableThreshold = 2;
    address[] owners;
    uint256[] ownerPks;

    uint256 webAuthnThreshold = 1;
    uint256[] pubKeysX;
    uint256[] pubKeysY;
    bool[] requireUVs;
    bytes32[] credentialIds;

    WebAuthn.WebAuthnAuth mockAuth;
    bytes mockWebAuthnSignature;
    bytes mockOwnableSignature;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        BaseTest.setUp();

        multiplexer = new StatelessValidatorMultiPlexer();
        ownableValidator = new OwnableValidator();
        webAuthnValidator = new WebAuthnValidator();

        _setupOwnableData();
        _setupWebAuthnData();
    }

    function _setupOwnableData() internal {
        owners = new address[](2);
        ownerPks = new uint256[](2);

        (address owner1, uint256 owner1Pk) = makeAddrAndKey("owner1");
        owners[0] = owner1;
        ownerPks[0] = owner1Pk;

        (address owner2, uint256 owner2Pk) = makeAddrAndKey("owner2");

        uint256 counter = 0;
        while (uint160(owner1) > uint160(owner2)) {
            counter++;
            (owner2, owner2Pk) = makeAddrAndKey(vm.toString(counter));
        }
        owners[1] = owner2;
        ownerPks[1] = owner2Pk;

        bytes32 hash = createTestHash();
        bytes memory signature1 = signHash(ownerPks[0], hash);
        bytes memory signature2 = signHash(ownerPks[1], hash);
        mockOwnableSignature = abi.encodePacked(signature1, signature2);
    }

    function _setupWebAuthnData() internal {
        pubKeysX = new uint256[](1);
        pubKeysY = new uint256[](1);
        requireUVs = new bool[](1);
        credentialIds = new bytes32[](1);

        pubKeysX[0] =
            66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805;
        pubKeysY[0] =
            46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186;
        requireUVs[0] = false;

        credentialIds[0] = webAuthnValidator.generateCredentialId(
            pubKeysX[0], pubKeysY[0], requireUVs[0], address(this)
        );

        bytes memory challenge = abi.encode(createTestHash());

        mockAuth = WebAuthn.WebAuthnAuth({
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

        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](1);
        sigs[0] = mockAuth;
        mockWebAuthnSignature = abi.encode(sigs);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstall() public {
        multiplexer.onInstall("");
        assertTrue(true);
    }

    function test_OnUninstall() public {
        multiplexer.onUninstall("");
        assertTrue(true);
    }

    function test_IsModuleTypeWhenTypeIdIs7() public view {
        bool isModuleType = multiplexer.isModuleType(7);
        assertTrue(isModuleType);
    }

    function test_IsModuleTypeWhenTypeIdIsNot7() public view {
        bool isModuleType = multiplexer.isModuleType(1);
        assertFalse(isModuleType);
    }

    function test_ValidateSignatureWithDataRevertWhen_ValidatorsAndDataLengthMismatch() public {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](2);
        validators[0] = address(ownableValidator);
        validators[1] = address(webAuthnValidator);

        bytes[] memory validatorData = new bytes[](1);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = mockOwnableSignature;
        signatures[1] = mockWebAuthnSignature;
        bytes memory signature = abi.encode(signatures);

        vm.expectRevert(StatelessValidatorMultiPlexer.MismatchedValidatorsAndDataLength.selector);
        multiplexer.validateSignatureWithData(hash, signature, data);
    }

    function test_ValidateSignatureWithDataRevertWhen_ValidatorsAndSignaturesLengthMismatch()
        public
    {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](2);
        validators[0] = address(ownableValidator);
        validators[1] = address(webAuthnValidator);

        bytes[] memory validatorData = new bytes[](2);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        WebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new WebAuthnValidator.WebAuthnCredential[](1);
        webAuthnCredentials[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: pubKeysX[0],
            pubKeyY: pubKeysY[0],
            requireUV: requireUVs[0]
        });

        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            usePrecompile: false,
            threshold: webAuthnThreshold,
            credentialIds: credentialIds,
            credentialData: webAuthnCredentials
        });
        validatorData[1] = abi.encode(context);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = mockOwnableSignature;
        bytes memory signature = abi.encode(signatures);

        vm.expectRevert(StatelessValidatorMultiPlexer.MismatchedValidatorsAndDataLength.selector);
        multiplexer.validateSignatureWithData(hash, signature, data);
    }

    function test_ValidateSignatureWithDataWhen_SingleValidatorFails() public {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](1);
        validators[0] = address(ownableValidator);

        bytes[] memory validatorData = new bytes[](1);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        bytes memory data = abi.encode(validators, validatorData);
        bytes memory invalidSignature =
            abi.encodePacked(signHash(uint256(1), hash), signHash(uint256(2), hash));

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = invalidSignature;
        bytes memory signature = abi.encode(signatures);

        bool isValid = multiplexer.validateSignatureWithData(hash, signature, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataWhen_SingleValidatorSucceeds() public view {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](1);
        validators[0] = address(ownableValidator);

        bytes[] memory validatorData = new bytes[](1);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = mockOwnableSignature;

        bool isValid = multiplexer.validateSignatureWithData(hash, abi.encode(signatures), data);
        assertTrue(isValid);
    }

    function test_ValidateSignatureWithDataWhen_MultipleValidatorsAllSucceed() public view {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](2);
        validators[0] = address(ownableValidator);
        validators[1] = address(webAuthnValidator);

        bytes[] memory validatorData = new bytes[](2);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        WebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new WebAuthnValidator.WebAuthnCredential[](1);
        webAuthnCredentials[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: pubKeysX[0],
            pubKeyY: pubKeysY[0],
            requireUV: requireUVs[0]
        });

        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            usePrecompile: false,
            threshold: webAuthnThreshold,
            credentialIds: credentialIds,
            credentialData: webAuthnCredentials
        });
        validatorData[1] = abi.encode(context);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = mockOwnableSignature;
        signatures[1] = mockWebAuthnSignature;
        bytes memory signature = abi.encode(signatures);

        bool isValid = multiplexer.validateSignatureWithData(hash, signature, data);
        assertTrue(isValid);
    }

    function test_ValidateSignatureWithDataWhen_FirstValidatorFailsSecondSucceeds() public {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](2);
        validators[0] = address(ownableValidator);
        validators[1] = address(webAuthnValidator);

        bytes[] memory validatorData = new bytes[](2);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        WebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new WebAuthnValidator.WebAuthnCredential[](1);
        webAuthnCredentials[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: pubKeysX[0],
            pubKeyY: pubKeysY[0],
            requireUV: requireUVs[0]
        });

        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            usePrecompile: false,
            threshold: webAuthnThreshold,
            credentialIds: credentialIds,
            credentialData: webAuthnCredentials
        });
        validatorData[1] = abi.encode(context);

        bytes memory data = abi.encode(validators, validatorData);
        bytes memory invalidOwnableSignature =
            abi.encodePacked(signHash(uint256(1), hash), signHash(uint256(2), hash));

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = invalidOwnableSignature;
        signatures[1] = mockWebAuthnSignature;
        bytes memory signature = abi.encode(signatures);

        bool isValid = multiplexer.validateSignatureWithData(hash, signature, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataWhen_FirstValidatorSucceedsSecondFails() public view {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](2);
        validators[0] = address(ownableValidator);
        validators[1] = address(webAuthnValidator);

        bytes[] memory validatorData = new bytes[](2);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        WebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new WebAuthnValidator.WebAuthnCredential[](1);
        webAuthnCredentials[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: 99_999,
            pubKeyY: 88_888,
            requireUV: false
        });

        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            usePrecompile: false,
            threshold: webAuthnThreshold,
            credentialIds: new bytes32[](1),
            credentialData: webAuthnCredentials
        });
        validatorData[1] = abi.encode(context);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = mockOwnableSignature;
        signatures[1] = mockWebAuthnSignature;
        bytes memory signature = abi.encode(signatures);

        bool isValid = multiplexer.validateSignatureWithData(hash, signature, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataWhen_NoValidators() public view {
        bytes32 hash = createTestHash();

        address[] memory validators = new address[](0);
        bytes[] memory validatorData = new bytes[](0);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](0);
        bytes memory signature = abi.encode(signatures);

        bool isValid = multiplexer.validateSignatureWithData(hash, signature, data);
        assertTrue(isValid);
    }

    function test_ValidateSignatureWithDataWhen_ThreeValidatorsAllSucceed() public {
        bytes32 hash = createTestHash();

        OwnableValidator anotherOwnableValidator = new OwnableValidator();

        address[] memory validators = new address[](3);
        validators[0] = address(ownableValidator);
        validators[1] = address(webAuthnValidator);
        validators[2] = address(anotherOwnableValidator);

        bytes[] memory validatorData = new bytes[](3);
        validatorData[0] = abi.encode(ownableThreshold, owners);

        WebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new WebAuthnValidator.WebAuthnCredential[](1);
        webAuthnCredentials[0] = WebAuthnValidator.WebAuthnCredential({
            pubKeyX: pubKeysX[0],
            pubKeyY: pubKeysY[0],
            requireUV: requireUVs[0]
        });

        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            usePrecompile: false,
            threshold: webAuthnThreshold,
            credentialIds: credentialIds,
            credentialData: webAuthnCredentials
        });
        validatorData[1] = abi.encode(context);

        validatorData[2] = abi.encode(1, owners);

        bytes memory data = abi.encode(validators, validatorData);

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = mockOwnableSignature;
        signatures[1] = mockWebAuthnSignature;
        signatures[2] = mockOwnableSignature;
        bytes memory signature = abi.encode(signatures);

        bool isValid = multiplexer.validateSignatureWithData(hash, signature, data);
        assertTrue(isValid);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    HELPERS
    //////////////////////////////////////////////////////////////////////////*/

    function createTestHash() internal pure returns (bytes32) {
        return bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
    }
}
