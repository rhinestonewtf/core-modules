// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { WebAuthnValidator } from "src/WebAuthnValidator/WebAuthnValidator.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { IModule as IERC7579Module } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

contract WebAuthnValidatorTest is BaseTest {
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

    // Deterministically generated credential IDs (computed in setUp)
    bytes32[] _credentialIds;

    // Mock WebAuthn signature data
    WebAuthn.WebAuthnAuth mockAuth;

    // Mock signature data for testing
    bytes mockSignatureData;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        BaseTest.setUp();
        validator = new WebAuthnValidator();

        // Initialize credential arrays
        _pubKeysX = new uint256[](2);
        _pubKeysY = new uint256[](2);
        _requireUVs = new bool[](2);
        _credentialIds = new bytes32[](2);

        // Use real public keys from WebAuthn test
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
        for (uint256 i = 0; i < 2; i++) {
            _credentialIds[i] = validator.generateCredentialId(
                _pubKeysX[i], _pubKeysY[i], _requireUVs[i], address(this)
            );
        }

        // Use a fixed challenge for testing
        bytes memory challenge =
            abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Set up real WebAuthn authentication data
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

        // Create WebAuthn signature data
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });

        // Use a slightly different signature for the second credential
        WebAuthn.WebAuthnAuth memory mockAuth2 = WebAuthn.WebAuthnAuth({
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

        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth2
        });

        // Create the new signature format that includes the credential IDs:
        // abi.encode(credentialIds, abi.encode(signatures))
        mockSignatureData = abi.encode(_credentialIds, abi.encode(sigs));
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    function test_GenerateCredentialId() public view {
        // Test that credential ID generation is deterministic
        bytes32 credId = validator.generateCredentialId(
            _pubKeysX[0], _pubKeysY[0], _requireUVs[0], address(this)
        );

        assertEq(credId, _credentialIds[0], "Credential ID generation should be deterministic");

        // Test that different parameters produce different credential IDs
        bytes32 credId2 = validator.generateCredentialId(
            _pubKeysX[0],
            _pubKeysY[0],
            _requireUVs[0],
            address(1) // Different address
        );

        assertTrue(credId != credId2, "Different addresses should produce different credential IDs");
    }

    function test_OnInstallRevertWhen_ModuleIsInitialized() public {
        // Install the module first
        bytes memory data = abi.encode(_threshold, _pubKeysX, _pubKeysY, _requireUVs);
        validator.onInstall(data);

        // Try to install again and expect revert
        vm.expectRevert();
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_ThresholdIs0() public whenModuleIsNotInitialized {
        // Create data with threshold = 0
        bytes memory data = abi.encode(0, _pubKeysX, _pubKeysY, _requireUVs);

        vm.expectRevert(WebAuthnValidator.ThresholdNotSet.selector);
        validator.onInstall(data);
    }

    function test_OnInstallWhenThresholdIsValid() public whenModuleIsNotInitialized {
        // Should set the threshold
        bytes memory data = abi.encode(_threshold, _pubKeysX, _pubKeysY, _requireUVs);
        validator.onInstall(data);

        uint256 threshold = validator.threshold(address(this));
        assertEq(threshold, _threshold, "Threshold should be set correctly");
    }

    function test_OnInstallRevertWhen_CredentialsLengthIsLessThanThreshold()
        public
        whenModuleIsNotInitialized
    {
        // Create data with threshold > credentials length
        bytes memory data = abi.encode(3, _pubKeysX, _pubKeysY, _requireUVs);

        vm.expectRevert(WebAuthnValidator.InvalidThreshold.selector);
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_CredentialsLengthIsMoreThanMax()
        public
        whenModuleIsNotInitialized
    {
        // Create arrays with 33 credentials (exceeding MAX_CREDENTIALS)
        uint256[] memory pubKeysX = new uint256[](33);
        uint256[] memory pubKeysY = new uint256[](33);
        bool[] memory requireUVs = new bool[](33);

        for (uint256 i = 0; i < 33; i++) {
            pubKeysX[i] = i + 1000;
            pubKeysY[i] = i + 2000;
            requireUVs[i] = (i % 2 == 0); // Alternate true/false
        }

        bytes memory data = abi.encode(_threshold, pubKeysX, pubKeysY, requireUVs);

        vm.expectRevert(WebAuthnValidator.MaxCredentialsReached.selector);
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_PubKeyIsZero() public whenModuleIsNotInitialized {
        // Create arrays with zero X pubkey
        uint256[] memory pubKeysX = new uint256[](2);
        pubKeysX[0] = 0; // Zero pubkey
        pubKeysX[1] = _pubKeysX[1];

        bytes memory data = abi.encode(_threshold, pubKeysX, _pubKeysY, _requireUVs);

        vm.expectRevert(WebAuthnValidator.InvalidPublicKey.selector);
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_CredentialsNotUnique() public whenModuleIsNotInitialized {
        // Create arrays with duplicate credentials (same pubKeyX, pubKeyY, requireUV)
        uint256[] memory pubKeysX = new uint256[](2);
        uint256[] memory pubKeysY = new uint256[](2);
        bool[] memory requireUVs = new bool[](2);

        pubKeysX[0] = _pubKeysX[0];
        pubKeysX[1] = _pubKeysX[0];
        pubKeysY[0] = _pubKeysY[0];
        pubKeysY[1] = _pubKeysY[0];
        requireUVs[0] = _requireUVs[0];
        requireUVs[1] = _requireUVs[0];

        bytes memory data = abi.encode(_threshold, pubKeysX, pubKeysY, requireUVs);

        vm.expectRevert(WebAuthnValidator.NotUnique.selector);
        validator.onInstall(data);
    }

    function test_OnInstallWhenCredentialsAreValid() public whenModuleIsNotInitialized {
        // Should add credentials and set up validator correctly
        bytes memory data = abi.encode(_threshold, _pubKeysX, _pubKeysY, _requireUVs);
        validator.onInstall(data);

        // Check credentials were added
        bytes32[] memory credIds = validator.getCredentialIds(address(this));
        assertEq(credIds.length, _pubKeysX.length, "Credential count should match");

        // Verify the credential IDs match what we expect
        bool foundCred0 = false;
        bool foundCred1 = false;

        for (uint256 i = 0; i < credIds.length; i++) {
            if (credIds[i] == _credentialIds[0]) foundCred0 = true;
            if (credIds[i] == _credentialIds[1]) foundCred1 = true;
        }

        assertTrue(foundCred0, "First credential should be found");
        assertTrue(foundCred1, "Second credential should be found");

        // Check first credential exists with correct data
        (uint256 pubKeyX, uint256 pubKeyY, bool requireUV) =
            validator.getCredentialInfo(_credentialIds[0], address(this));
        assertEq(pubKeyX, _pubKeysX[0], "Public key X should match");
        assertEq(pubKeyY, _pubKeysY[0], "Public key Y should match");
        assertEq(requireUV, _requireUVs[0], "RequireUV should match");
    }

    function test_OnUninstallShouldRemoveAllCredentials() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Then uninstall
        validator.onUninstall("");

        // Check credentials were removed
        bytes32[] memory credIds = validator.getCredentialIds(address(this));
        assertEq(credIds.length, 0, "All credentials should be removed");
    }

    function test_OnUninstallShouldSetThresholdTo0() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Then uninstall
        validator.onUninstall("");

        // Check threshold is 0
        uint256 threshold = validator.threshold(address(this));
        assertEq(threshold, 0, "Threshold should be reset to 0");
    }

    function test_IsInitializedWhenModuleIsNotInitialized() public view {
        // Should return false when not initialized
        bool isInitialized = validator.isInitialized(address(this));
        assertFalse(isInitialized, "Module should not be initialized");
    }

    function test_IsInitializedWhenModuleIsInitialized() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should return true when initialized
        bool isInitialized = validator.isInitialized(address(this));
        assertTrue(isInitialized, "Module should be initialized");
    }

    function test_SetThresholdRevertWhen_ModuleIsNotInitialized() public {
        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.setThreshold(1);
    }

    function test_SetThresholdRevertWhen_ThresholdIs0() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should revert
        vm.expectRevert(WebAuthnValidator.InvalidThreshold.selector);
        validator.setThreshold(0);
    }

    function test_SetThresholdRevertWhen_ThresholdIsHigherThanCredentialsCount()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should revert
        vm.expectRevert(WebAuthnValidator.InvalidThreshold.selector);
        validator.setThreshold(10);
    }

    function test_SetThresholdWhenThresholdIsValid() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Get current threshold
        uint256 oldThreshold = validator.threshold(address(this));
        uint256 newThreshold = 1;
        assertNotEq(oldThreshold, newThreshold, "New threshold should be different");

        // Set threshold
        validator.setThreshold(newThreshold);

        // Check threshold
        assertEq(validator.threshold(address(this)), newThreshold, "Threshold should be updated");
    }

    function test_AddCredentialRevertWhen_ModuleIsNotInitialized() public {
        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.addCredential(99_999, 88_888, true);
    }

    function test_AddCredentialRevertWhen_PubKeyIsZero() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should revert when X is 0
        vm.expectRevert(WebAuthnValidator.InvalidPublicKey.selector);
        validator.addCredential(0, 88_888, true);

        // Should revert when Y is 0
        vm.expectRevert(WebAuthnValidator.InvalidPublicKey.selector);
        validator.addCredential(99_999, 0, true);
    }

    function test_AddCredentialRevertWhen_CredentialCountIsMoreThanMax()
        public
        whenModuleIsInitialized
    {
        // Create and install module with 32 credentials
        uint256[] memory pubKeysX = new uint256[](32);
        uint256[] memory pubKeysY = new uint256[](32);
        bool[] memory requireUVs = new bool[](32);

        for (uint256 i = 0; i < 32; i++) {
            pubKeysX[i] = i + 1000;
            pubKeysY[i] = i + 2000;
            requireUVs[i] = (i % 2 == 0); // Alternate true/false
        }

        bytes memory data = abi.encode(1, pubKeysX, pubKeysY, requireUVs);
        validator.onInstall(data);

        // Try to add one more credential
        vm.expectRevert(WebAuthnValidator.MaxCredentialsReached.selector);
        validator.addCredential(99_999, 88_888, true);
    }

    function test_AddCredentialRevertWhen_CredentialAlreadyExists()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Try to add a credential that already exists
        vm.expectRevert(WebAuthnValidator.CredentialAlreadyExists.selector);
        validator.addCredential(_pubKeysX[0], _pubKeysY[0], _requireUVs[0]);
    }

    function test_AddCredentialWhenCredentialIsValid() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Add new credential
        uint256 newPubKeyX = 99_999;
        uint256 newPubKeyY = 88_888;
        bool newRequireUV = true;

        validator.addCredential(newPubKeyX, newPubKeyY, newRequireUV);

        // Compute the credential ID
        bytes32 newCredentialId =
            validator.generateCredentialId(newPubKeyX, newPubKeyY, newRequireUV, address(this));

        // Check credential was added
        assertTrue(
            validator.hasCredential(newPubKeyX, newPubKeyY, newRequireUV, address(this)),
            "Should have credential by parameters"
        );

        assertTrue(
            validator.hasCredentialById(newCredentialId, address(this)),
            "Should have credential by ID"
        );

        // Check credential info
        (uint256 pubKeyX, uint256 pubKeyY, bool requireUV) =
            validator.getCredentialInfo(newCredentialId, address(this));
        assertEq(pubKeyX, newPubKeyX, "Public key X should match");
        assertEq(pubKeyY, newPubKeyY, "Public key Y should match");
        assertEq(requireUV, newRequireUV, "RequireUV should match");

        // Check credential count
        assertEq(validator.getCredentialCount(address(this)), 3, "Credential count should be 3");
    }

    function test_RemoveCredentialRevertWhen_ModuleIsNotInitialized() public {
        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.removeCredential(99_999, 88_888, true);
    }

    function test_RemoveCredentialRevertWhen_CredentialDoesNotExist()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Try to remove a credential that doesn't exist
        vm.expectRevert(WebAuthnValidator.CannotRemoveCredential.selector);
        validator.removeCredential(99_999, 88_888, true);
    }

    function test_RemoveCredentialRevertWhen_RemovalWouldBreakThreshold()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // We have 2 credentials with threshold 2, so removing any would break threshold
        vm.expectRevert(WebAuthnValidator.CannotRemoveCredential.selector);
        validator.removeCredential(_pubKeysX[0], _pubKeysY[0], _requireUVs[0]);
    }

    function test_RemoveCredentialWhenRemovalWouldNotBreakThreshold()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Lower threshold so we can remove a credential
        validator.setThreshold(1);

        // Remove a credential
        validator.removeCredential(_pubKeysX[0], _pubKeysY[0], _requireUVs[0]);

        // Check credential was removed
        assertFalse(
            validator.hasCredential(_pubKeysX[0], _pubKeysY[0], _requireUVs[0], address(this)),
            "Credential should be removed"
        );

        assertFalse(
            validator.hasCredentialById(_credentialIds[0], address(this)),
            "Credential should be removed by ID check"
        );

        // Check credential count
        assertEq(validator.getCredentialCount(address(this)), 1, "Credential count should be 1");
    }

    function test_GetCredentialIds() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Get credential IDs
        bytes32[] memory credIds = validator.getCredentialIds(address(this));

        // Check length
        assertEq(credIds.length, _credentialIds.length, "Should have correct number of credentials");

        // Check IDs match (may be in different order due to set storage)
        bool found0 = false;
        bool found1 = false;

        for (uint256 i = 0; i < credIds.length; i++) {
            if (credIds[i] == _credentialIds[0]) found0 = true;
            if (credIds[i] == _credentialIds[1]) found1 = true;
        }

        assertTrue(found0, "First credential should be found");
        assertTrue(found1, "Second credential should be found");
    }

    function test_HasCredential() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Check existing credential by parameters
        assertTrue(
            validator.hasCredential(_pubKeysX[0], _pubKeysY[0], _requireUVs[0], address(this)),
            "Should have first credential"
        );

        // Check existing credential by ID
        assertTrue(
            validator.hasCredentialById(_credentialIds[0], address(this)),
            "Should have first credential by ID"
        );

        // Check non-existent credential
        assertFalse(
            validator.hasCredential(99_999, 88_888, true, address(this)),
            "Should not have non-existent credential"
        );
    }

    function test_GetCredentialCount() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Check credential count
        assertEq(validator.getCredentialCount(address(this)), 2, "Should have 2 credentials");

        // Add a credential
        validator.addCredential(99_999, 88_888, true);

        // Check updated credential count
        assertEq(validator.getCredentialCount(address(this)), 3, "Should have 3 credentials");
    }

    function test_GetCredentialInfo() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Get credential info
        (uint256 pubKeyX, uint256 pubKeyY, bool requireUV) =
            validator.getCredentialInfo(_credentialIds[0], address(this));

        // Check info matches
        assertEq(pubKeyX, _pubKeysX[0], "Public key X should match");
        assertEq(pubKeyY, _pubKeysY[0], "Public key Y should match");
        assertEq(requireUV, _requireUVs[0], "RequireUV should match");
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    function test_IsModuleType() public view {
        // Test validation type
        assertTrue(
            validator.isModuleType(uint256(1)), // TYPE_VALIDATOR
            "Should return true for TYPE_VALIDATOR"
        );

        // Test stateless validation type
        assertTrue(
            validator.isModuleType(uint256(7)), "Should return true for TYPE_STATELESS_VALIDATOR"
        );

        // Test invalid type
        assertFalse(validator.isModuleType(99), "Should return false for invalid type");
    }

    function test_Name() public view {
        string memory name = validator.name();
        assertEq(name, "WebAuthnValidator", "Name should be WebAuthnValidator");
    }

    function test_Version() public view {
        string memory version = validator.version();
        assertEq(version, "1.0.0", "Version should be 1.0.0");
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_ValidateUserOpWhenThresholdIsNotSet() public view {
        // should return VALIDATION_FAILED
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData, uint256(1), "Should return VALIDATION_FAILED when threshold is not set"
        );
    }

    function test_ValidateUserOpWhenSignaturesAreNotInOrderWithCredentials()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a user operation with invalid signatures
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create signature data with credentials in wrong order
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth
        });
        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });

        // But still use the correct order in the outer array
        userOp.signature = abi.encode(_credentialIds, abi.encode(sigs));

        // Validation should fail because the signature data doesn't match
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData,
            uint256(1),
            "Should return VALIDATION_FAILED when signatures are not in order"
        );
    }

    function test_ValidateUserOpWhenNotEnoughValidSignatures() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a user operation with invalid signatures
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create signature data with only 1 valid signature (threshold is 2)
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });
        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth
        });

        // Encode the signatures
        (bytes32[] memory credIds,) = abi.decode(mockSignatureData, (bytes32[], bytes));
        userOp.signature = abi.encode(credIds, abi.encode(sigs));

        // Validation should fail because we need 2 valid signatures
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData,
            uint256(1),
            "Should return VALIDATION_FAILED when not enough valid signatures"
        );
    }

    function test_IsValidSignatureWithSenderWhenThresholdIsNotSet() public view {
        // Should return EIP1271_FAILED
        bytes32 hash = bytes32(keccak256("test message"));
        bytes memory data = "";

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(
            result, EIP1271_MAGIC_VALUE, "Should return EIP1271_FAILED when threshold is not set"
        );
    }

    function test_IsValidSignatureWithSenderWhenSignaturesAreNotInOrderWithCredentials()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a message hash
        bytes32 hash = bytes32(keccak256("test message"));

        // Create signature data with credentials in wrong order
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth
        });
        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });

        // But still use the correct order in the outer array
        bytes memory signature = abi.encode(_credentialIds, abi.encode(sigs));

        // Validation should fail
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, signature);
        assertNotEq(
            result,
            EIP1271_MAGIC_VALUE,
            "Should return EIP1271_FAILED when signatures are not in order"
        );
    }

    function test_IsValidSignatureWithSenderWhenNotEnoughValidSignatures()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a message hash
        bytes32 hash = bytes32(keccak256("test message"));

        // Create signature data with only 1 valid signature (threshold is 2)
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });
        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth
        });

        // Encode the signatures
        (bytes32[] memory credIds,) = abi.decode(mockSignatureData, (bytes32[], bytes));
        bytes memory signature = abi.encode(credIds, abi.encode(sigs));

        // Validation should fail because we need 2 valid signatures
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, signature);
        assertNotEq(
            result,
            EIP1271_MAGIC_VALUE,
            "Should return EIP1271_FAILED when not enough valid signatures"
        );
    }

    function test_ValidateSignatureWithDataWhenArrayLengthsDontMatch() public view {
        // Should return false when credential IDs and credential data arrays have different lengths
        bytes32 hash = bytes32(keccak256("test message"));
        bytes memory signature = "";

        // Create verification context with mismatched arrays
        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            threshold: 2,
            credentialIds: new bytes32[](2),
            credentialData: new WebAuthnValidator.WebAuthnCredential[](1) // Different length!
         });

        bytes memory data = abi.encode(context);

        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when array lengths don't match");
    }

    function test_ValidateSignatureWithDataWhenThresholdIsInvalid() public view {
        // Should return false when threshold is 0 or greater than credentials length
        bytes32 hash = bytes32(keccak256("test message"));
        bytes memory signature = "";

        // Prepare credential arrays
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

        // Case 1: Threshold is 0
        WebAuthnValidator.WebAuthVerificationContext memory context1 = WebAuthnValidator
            .WebAuthVerificationContext({
            threshold: 0, // Invalid threshold
            credentialIds: credentialIds,
            credentialData: credentialData
        });

        bytes memory data1 = abi.encode(context1);
        bool result1 = validator.validateSignatureWithData(hash, signature, data1);
        assertFalse(result1, "Should return false when threshold is 0");

        // Case 2: Threshold is greater than credentials length
        WebAuthnValidator.WebAuthVerificationContext memory context2 = WebAuthnValidator
            .WebAuthVerificationContext({
            threshold: 3, // Invalid threshold (> credentials length)
            credentialIds: credentialIds,
            credentialData: credentialData
        });

        bytes memory data2 = abi.encode(context2);
        bool result2 = validator.validateSignatureWithData(hash, signature, data2);
        assertFalse(
            result2, "Should return false when threshold is greater than credentials length"
        );
    }

    function test_ValidateSignatureWithDataWhenSignaturesAreNotInOrderWithCredentials()
        public
        view
    {
        // Should return false when signatures don't match credential order
        bytes32 hash = bytes32(keccak256("test message"));

        // Prepare credential arrays with correct data
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

        // Create signature data with credentials in wrong order
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        // Swap the credential IDs
        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth
        });
        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });

        // Encode the signatures
        bytes memory signature = abi.encode(sigs);

        // Context with valid threshold
        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            threshold: 2,
            credentialIds: credentialIds,
            credentialData: credentialData
        });

        bytes memory data = abi.encode(context);

        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when signatures are not in order with credentials");
    }

    function test_ValidateSignatureWithDataWhenNotEnoughValidSignatures() public view {
        // Should return false when not enough valid signatures are provided
        bytes32 hash = bytes32(keccak256("test message"));

        // Prepare credential arrays with correct data
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

        // Create signature data
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);

        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });
        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth
        });

        // Encode the signatures
        bytes memory signature = abi.encode(sigs);

        // Context with valid threshold
        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            threshold: 2,
            credentialIds: credentialIds,
            credentialData: credentialData
        });

        bytes memory data = abi.encode(context);

        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when not enough valid signatures are provided");
    }

    function test_ValidateUserOpWhenEnoughValidSignaturesAreProvided()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a user operation with valid signatures
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        // Use a fixed challenge that matches our WebAuthn signatures
        bytes32 userOpHash = createTestUserOpHash();

        // Use our pre-encoded valid signatures
        userOp.signature = mockSignatureData;

        // Validation should succeed with our real WebAuthn signatures
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData,
            uint256(0),
            "Should return VALIDATION_SUCCESS when enough valid signatures"
        );
    }

    function test_IsValidSignatureWithSenderWhenEnoughValidSignaturesAreProvided()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a message hash that matches our WebAuthn challenge
        bytes32 hash = createTestUserOpHash();

        // Use our pre-encoded valid signatures
        bytes memory signature = mockSignatureData;

        // Validation should succeed with our real WebAuthn signatures
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, signature);
        assertEq(
            result,
            EIP1271_MAGIC_VALUE,
            "Should return EIP1271_SUCCESS when enough valid signatures"
        );
    }

    function test_ValidateSignatureWithDataWhenEnoughValidSignaturesAreProvidedInOrder()
        public
        view
    {
        // Create a message hash that matches our WebAuthn challenge
        bytes32 hash = createTestUserOpHash();

        // Prepare credential arrays with the correct public keys
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

        // Use our pre-encoded valid signatures
        (, bytes memory signature) = abi.decode(mockSignatureData, (bytes32, bytes));

        // Context with valid threshold
        WebAuthnValidator.WebAuthVerificationContext memory context = WebAuthnValidator
            .WebAuthVerificationContext({
            threshold: 2,
            credentialIds: credentialIds,
            credentialData: credentialData
        });

        bytes memory data = abi.encode(context);

        // Validation should succeed with our real WebAuthn signatures
        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertTrue(result, "Should return true when enough valid signatures are provided in order");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    MODIFIERS
    //////////////////////////////////////////////////////////////////////////*/

    modifier whenModuleIsNotInitialized() {
        _;
    }

    modifier whenModuleIsInitialized() {
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function createTestUserOpHash() internal pure returns (bytes32) {
        return bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
    }
}
