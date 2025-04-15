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
            54_807_504_639_157_773_171_177_224_001_212_008_597_433_484_848_616_288_761_862_685_500_185_651_332_983;
        _pubKeysY[0] =
            242_821_441_213_993_241_301_867_916_017_299_895_973_570_424_776_011_613_598_955_485_413_223_728_653;
        _requireUVs[0] = true;

        _pubKeysX[1] =
            66_516_957_811_183_209_107_370_411_064_969_222_874_919_604_068_615_673_272_710_358_317_257_245_599_632;
        _pubKeysY[1] =
            71_625_993_437_896_297_654_335_703_614_222_352_668_480_151_708_606_449_261_273_819_495_316_231_590_774;
        _requireUVs[1] = false;

        // Pre-compute credential IDs for testing
        for (uint256 i = 0; i < 2; i++) {
            _credentialIds[i] = validator.generateCredentialId(
                _pubKeysX[i], _pubKeysY[i], _requireUVs[i], address(this)
            );
        }

        // Use a fixed challenge for testing
        bytes memory challenge =
            abi.encode(bytes32(bytes(("9jEFijuhEWrM4SOW-tChJbUEHEP44VcjcJ-Bqo1fTM8"))));

        // Set up real WebAuthn authentication data
        mockAuth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                '","origin":"http://localhost:3005"}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 25_812_802_015_954_623_097_390_139_586_389_273_967_116_245_496_476_953_348_223_000_448_619_515_908_322,
            s: 18_958_476_174_746_756_540_810_015_776_648_243_959_108_274_224_858_350_275_711_600_244_636_459_694_113
        });

        // Create mock signature data - encode it directly to avoid compiler limitations
        // This creates mock data for two signatures that will be decoded during validation
        WebAuthnValidator.WebAuthnSignatureData[] memory sigs =
            new WebAuthnValidator.WebAuthnSignatureData[](2);
        sigs[0] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[0],
            auth: mockAuth
        });

        // Use a slightly different signature for the second credential
        WebAuthn.WebAuthnAuth memory mockAuth2 = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                '","origin":"http://localhost:3005","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 98_518_400_801_405_136_947_761_206_324_368_310_068_820_329_541_334_119_522_740_223_463_953_495_491_956,
            s: 18_381_529_304_872_271_321_928_375_352_427_217_698_453_657_984_149_443_593_404_558_549_205_571_840_728
        });

        sigs[1] = WebAuthnValidator.WebAuthnSignatureData({
            credentialId: _credentialIds[1],
            auth: mockAuth2
        });

        // Encode the signatures
        mockSignatureData = abi.encode(sigs);
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

    function test_ValidateUserOpWhenThresholdIsNotSet() public {
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
        userOp.signature = abi.encode(sigs);

        // Validation should fail
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
        userOp.signature = abi.encode(sigs);

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
        bytes memory signature = abi.encode(sigs);

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
        bytes memory signature = mockSignatureData;

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
        return bytes32(bytes("9jEFijuhEWrM4SOW-tChJbUEHEP44VcjcJ-Bqo1fTM8"));
    }
}
