// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

// Contracts
import { ERC7579HybridValidatorBase } from "modulekit/Modules.sol";

// Types
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";

// Libraries
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { CheckSignatures } from "checknsignatures/CheckNSignatures.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { WebAuthn, WebAuthnAuth } from "@webauthn/WebAuthn.sol";

uint256 constant TYPE_STATELESS_VALIDATOR = 7;

/// @title WebAuthnValidator
/// @author Based on Rhinestone's OwnableValidator
/// @notice A validator module that enables WebAuthn (passkey) authentication with threshold support
/// @dev Module allows smart accounts to authenticate using one or more WebAuthn credentials
///     (passkeys) with support for M-of-N threshold signatures.
contract WebAuthnValidator is ERC7579HybridValidatorBase {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using LibSort for bytes32[];
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using WebAuthn for bytes;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Structure holding WebAuthn credential information
    /// @dev Maps a credential ID to its public key and verification requirements
    /// @param pubKeyX The X coordinate of the credential's public key on the P-256 curve
    /// @param pubKeyY The Y coordinate of the credential's public key on the P-256 curve
    /// @param requireUV Whether user verification (biometrics/PIN) is required for this credential
    struct WebAuthnCredential {
        uint256 pubKeyX;
        uint256 pubKeyY;
        bool requireUV;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the module is installed for an account
    event ModuleInitialized(address indexed account);

    /// @notice Emitted when the module is uninstalled for an account
    event ModuleUninitialized(address indexed account);

    /// @notice Emitted when a threshold is set for an account
    /// @param account The address of the smart account
    /// @param threshold The new threshold value
    event ThresholdSet(address indexed account, uint256 threshold);

    /// @notice Emitted when a credential is added to an account
    /// @param account The address of the smart account
    /// @param credentialId The ID of the added credential
    event CredentialAdded(address indexed account, bytes32 indexed credentialId);

    /// @notice Emitted when a credential is removed from an account
    /// @param account The address of the smart account
    /// @param credentialId The ID of the removed credential
    event CredentialRemoved(address indexed account, bytes32 indexed credentialId);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when attempting to set a zero threshold
    error ThresholdNotSet();

    /// @notice Thrown when a threshold is invalid (e.g., higher than credential count)
    error InvalidThreshold();

    /// @notice Thrown when credential IDs are not sorted and unique
    error NotSortedAndUnique();

    /// @notice Thrown when attempting to add more credentials than the maximum allowed
    error MaxCredentialsReached();

    /// @notice Thrown when an invalid credential ID is provided
    /// @param credentialId The ID of the invalid credential
    error InvalidCredential(bytes32 credentialId);

    /// @notice Thrown when the trying to remove a credential would make the threshold unreachable
    error CannotRemoveCredential();

    /// @notice Thrown when an invalid public key is provided
    error InvalidPublicKey();

    /// @notice Thrown when a credential already exists
    error CredentialAlreadyExists();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum number of credentials allowed per account
    uint256 constant MAX_CREDENTIALS = 32;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    ///.@notice Enumerable set of enabled credentials per account
    EnumerableSet.Bytes32Set credentials;

    /// @notice Mapping of credential IDs to their respective WebAuthn credentials
    mapping(bytes32 credentialId => mapping(address account => WebAuthnCredential credential))
        public credentialDetails;

    /// @notice Threshold for each account
    mapping(address account => uint256 threshold) public threshold;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the module with WebAuthn credentials
    /// @dev Installs the validator with threshold and initial set of credentials
    /// @param data Encoded as: abi.encode(threshold, credentialIds, pubKeysX, pubKeysY, requireUVs)
    function onInstall(bytes calldata data) external override {
        // Decode the credential data
        (
            uint256 _threshold,
            bytes32[] memory _credentialIds,
            uint256[] memory _pubKeysX,
            uint256[] memory _pubKeysY,
            bool[] memory _requireUVs
        ) = abi.decode(data, (uint256, bytes32[], uint256[], uint256[], bool[]));

        // Check that credential arrays are of same length
        uint256 credentialsLength = _credentialIds.length;
        if (
            credentialsLength != _pubKeysX.length || credentialsLength != _pubKeysY.length
                || credentialsLength != _requireUVs.length
        ) {
            revert NotSortedAndUnique();
        }

        // Check that credentials are sorted and unique
        if (!_credentialIds.isSortedAndUnique()) {
            revert NotSortedAndUnique();
        }

        // Make sure the threshold is set
        if (_threshold == 0) {
            revert ThresholdNotSet();
        }

        // Make sure the threshold is valid
        if (credentialsLength < _threshold) {
            revert InvalidThreshold();
        }

        // Check if max credentials is reached
        if (credentialsLength > MAX_CREDENTIALS) {
            revert MaxCredentialsReached();
        }

        // Cache the account address
        address account = msg.sender;

        // Set threshold
        threshold[account] = _threshold;

        // Add credentials
        for (uint256 i = 0; i < credentialsLength; i++) {
            bytes32 credId = _credentialIds[i];

            // Check credential ID is valid
            if (credId == bytes32(0)) {
                revert InvalidCredential(credId);
            }

            // Check public key is valid
            if (_pubKeysX[i] == 0 || _pubKeysY[i] == 0) {
                revert InvalidPublicKey();
            }

            // Store the credential
            credentialDetails[credId][account] = WebAuthnCredential({
                pubKeyX: _pubKeysX[i],
                pubKeyY: _pubKeysY[i],
                requireUV: _requireUVs[i]
            });

            // Add credential ID to the set
            credentials.add(account, credId);

            // Emit event
            emit CredentialAdded(account, credId);
        }

        emit ModuleInitialized(account);
    }

    /// @notice Handles the uninstallation of the module and clears all credentials
    /// @dev Removes all credentials and settings for the account
    /// @param Unused but required by interface
    function onUninstall(bytes calldata) external override {
        // Cache the account address
        address account = msg.sender;

        // Get all credentials to clear mappings
        bytes32[] memory credentialsIds = getCredentialIds(account);

        // Clear the credentials mapping
        for (uint256 i = 0; i < credentialsIds.length; i++) {
            delete credentialDetails[credentialsIds[i]][account];
        }

        // Remove all credentials from the set
        credentials.removeAll(account);

        // Remove the threshold
        threshold[account] = 0;

        emit ModuleUninitialized(account);
    }

    /// @notice Checks if the module is initialized for a smart account
    /// @param smartAccount Address of the smart account
    /// @return bool True if the module is initialized, false otherwise
    function isInitialized(address smartAccount) public view returns (bool) {
        return threshold[smartAccount] != 0;
    }

    /// @notice Sets the threshold for the account
    /// @dev Updates how many signatures are required to validate operations
    /// @param _threshold Number of required signatures
    function setThreshold(uint256 _threshold) external {
        // Cache the account address
        address account = msg.sender;

        // Check if the module is initialized
        if (!isInitialized(account)) revert NotInitialized(account);

        // Make sure the threshold is set
        if (_threshold == 0) {
            revert InvalidThreshold();
        }

        // Make sure the threshold is less than the number of credentials
        if (credentials.length(account) < _threshold) {
            revert InvalidThreshold();
        }

        // Set the threshold
        threshold[account] = _threshold;

        emit ThresholdSet(account, _threshold);
    }

    /// @notice Adds a WebAuthn credential to the account
    /// @dev Registers a new passkey for authentication
    /// @param credentialId Unique identifier for the WebAuthn credential
    /// @param pubKeyX X coordinate of the credential's public key
    /// @param pubKeyY Y coordinate of the credential's public key
    /// @param requireUV Whether user verification (biometrics/PIN) is required
    function addCredential(
        bytes32 credentialId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        bool requireUV
    )
        external
    {
        // Cache the account address
        address account = msg.sender;

        // Check if the module is initialized
        if (!isInitialized(account)) revert NotInitialized(account);

        // Revert if the credential ID is invalid
        if (credentialId == bytes32(0)) {
            revert InvalidCredential(credentialId);
        }

        // Check if credential already exists
        if (credentials.contains(account, credentialId)) {
            revert CredentialAlreadyExists();
        }

        // Check if max credentials is reached
        if (credentials.length(account) >= MAX_CREDENTIALS) {
            revert MaxCredentialsReached();
        }

        // Verify public key is valid
        if (pubKeyX == 0 || pubKeyY == 0) {
            revert InvalidPublicKey();
        }

        // Store the credential
        credentialDetails[credentialId][account] =
            WebAuthnCredential({ pubKeyX: pubKeyX, pubKeyY: pubKeyY, requireUV: requireUV });

        // Add the credential ID to the set
        credentials.add(account, credentialId);

        emit CredentialAdded(account, credentialId);
    }

    /// @notice Removes a WebAuthn credential from the account
    /// @dev De-registers a passkey and prevents it from being used for authentication
    /// @param credentialId ID of the credential to remove
    function removeCredential(bytes32 credentialId) external {
        // Cache the account address
        address account = msg.sender;

        // Check if the module is initialized
        if (!isInitialized(account)) revert NotInitialized(account);

        // Check if credential exists
        if (!credentials.contains(account, credentialId)) {
            revert InvalidCredential(credentialId);
        }

        // Check if removing would break threshold
        if (credentials.length(account) <= threshold[account]) {
            revert CannotRemoveCredential();
        }

        // Remove the credential from the set
        credentials.remove(account, credentialId);

        // Delete from the credentials mapping
        delete credentialDetails[credentialId][account];

        emit CredentialRemoved(account, credentialId);
    }

    /// @notice Returns the credential IDs of the account
    /// @dev Gets all registered credential IDs for an account
    /// @param account Address of the account
    /// @return Array of credential IDs
    function getCredentialIds(address account)
        public
        view
        returns (bytes32[] memory credentialsIds)
    {
        return credentials.values(account);
    }

    /// @notice Returns the number of credentials for an account
    /// @param account Address of the account
    /// @return Count of credentials
    function getCredentialCount(address account) external view returns (uint256 count) {
        return credentials.length(account);
    }

    /// @notice Checks if a credential exists for an account
    /// @dev Verifies if a specific credential ID is registered
    /// @param credentialId Credential ID to check
    /// @param account Address of the account to check
    /// @return exists True if the credential exists, false otherwise
    function hasCredential(
        bytes32 credentialId,
        address account
    )
        external
        view
        returns (bool exists)
    {
        return credentials.contains(account, credentialId);
    }

    /// @dev Gets the public key and settings for a credential
    /// @param credentialId Credential ID to query
    /// @param account Address of the account
    /// @return pubKeyX X coordinate of the public key
    /// @return pubKeyY Y coordinate of the public key
    /// @return requireUV Whether user verification is required
    function getCredentialInfo(
        bytes32 credentialId,
        address account
    )
        external
        view
        returns (uint256 pubKeyX, uint256 pubKeyY, bool requireUV)
    {
        WebAuthnCredential memory cred = credentialDetails[credentialId][account];
        return (cred.pubKeyX, cred.pubKeyY, cred.requireUV);
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a user operation
    /// @dev Verifies WebAuthn signatures for ERC-4337 transactions
    /// @param userOp User operation to validate
    /// @param userOpHash Hash of the user operation
    /// @return ValidationData Result of validation (success or failure)
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        // Validate the signature
        bool isValid = _validateSignatureWithConfig(userOp.sender, userOpHash, userOp.signature);

        // Return the result
        if (isValid) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /// @notice Validates an ERC-1271 signature with the sender
    /// @dev Implements EIP-1271 isValidSignature for smart contract signatures
    /// @param _ Unused parameter (from interface)
    /// @param hash Hash of the data to validate
    /// @param data Signature data
    /// @return bytes4 EIP1271_SUCCESS if valid, EIP1271_FAILED otherwise
    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // Validate the signature
        bool isValid = _validateSignatureWithConfig(msg.sender, hash, data);

        // Return the result
        if (isValid) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /// @notice Validates a signature with external credential data
    /// @dev Used for stateless validation without pre-registered credentials
    /// @param hash Hash of the data to validate
    /// @param signature WebAuthn signature data
    /// @param data Encoded credential details and threshold
    /// @return bool True if the signature is valid, false otherwise
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        override
        returns (bool)
    {
        // Decode the threshold and credentials
        (
            uint256 _threshold,
            bytes32[] memory _credentialIds,
            uint256[] memory _pubKeysX,
            uint256[] memory _pubKeysY,
            bool[] memory _requireUVs
        ) = abi.decode(data, (uint256, bytes32[], uint256[], uint256[], bool[]));

        // Check that arrays have matching lengths
        uint256 credentialsLength = _credentialIds.length;
        if (
            credentialsLength != _pubKeysX.length || credentialsLength != _pubKeysY.length
                || credentialsLength != _requireUVs.length
        ) {
            return false;
        }

        // Check that threshold is valid
        if (_threshold == 0 || _threshold > credentialsLength) {
            return false;
        }

        // Verify WebAuthn signatures
        (bool success, uint256 validSigs) = _verifyWebAuthnSignatures(
            hash, signature, _threshold, _credentialIds, _pubKeysX, _pubKeysY, _requireUVs
        );

        if (!success) {
            return false;
        }

        // Check if threshold is met
        return validSigs >= _threshold;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature against the account's credentials
    /// @dev Internal function to verify WebAuthn signatures against registered keys
    /// @param account Address of the account
    /// @param hash Hash of the data to verify
    /// @param data Signature data
    /// @return bool True if signature is valid and meets threshold, false otherwise
    function _validateSignatureWithConfig(
        address account,
        bytes32 hash,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        // Get the threshold
        uint256 _threshold = threshold[account];
        if (_threshold == 0) {
            return false;
        }

        // Get credential IDs
        bytes32[] memory credIds = getCredentialIds(account);

        // Prepare arrays for verification
        uint256[] memory pubKeysX = new uint256[](credIds.length);
        uint256[] memory pubKeysY = new uint256[](credIds.length);
        bool[] memory requireUVs = new bool[](credIds.length);

        // Populate credential data
        for (uint256 i = 0; i < credIds.length; i++) {
            WebAuthnCredential memory cred = credentialDetails[credIds[i]][account];
            pubKeysX[i] = cred.pubKeyX;
            pubKeysY[i] = cred.pubKeyY;
            requireUVs[i] = cred.requireUV;
        }

        // Verify WebAuthn signatures
        (bool success, uint256 validSigs) = _verifyWebAuthnSignatures(
            hash, data, _threshold, credIds, pubKeysX, pubKeysY, requireUVs
        );

        if (!success) {
            return false;
        }

        // Check if threshold is met
        return validSigs >= _threshold;
    }

    /// @dev Core signature verification logic for WebAuthn authenticators
    /// @param hash Hash of the data to verify
    /// @param signatureData Encoded WebAuthn signatures
    /// @param thresholdValue Required number of valid signatures
    /// @param credIds Array of credential IDs
    /// @param pubKeysX Array of X coordinates for public keys
    /// @param pubKeysY Array of Y coordinates for public keys
    /// @param requireUVs Array of user verification requirements
    /// @return success Whether verification process completed successfully
    /// @return validCount Number of valid signatures found
    function _verifyWebAuthnSignatures(
        bytes32 hash,
        bytes calldata signatureData,
        uint256 thresholdValue,
        bytes32[] memory credIds,
        uint256[] memory pubKeysX,
        uint256[] memory pubKeysY,
        bool[] memory requireUVs
    )
        internal
        view
        returns (bool success, uint256 validCount)
    {
        // Decode the signature data
        // Format: abi.encode(signatures)
        bytes[] memory signatures = abi.decode(signatureData, (bytes[]));

        // Check number of signatures
        if (signatures.length == 0 || signatures.length < thresholdValue) {
            return (false, 0);
        }

        // Track valid signatures
        validCount = 0;

        // Verify each signature
        for (uint256 i = 0; i < signatures.length; i++) {
            // Decode the individual signature
            // Format: abi.encode(credentialId, webAuthnAuth)
            (bytes32 credentialId, WebAuthnAuth memory auth) =
                abi.decode(signatures[i], (bytes32, WebAuthnAuth));

            // Find the credential in the provided list
            uint256 credIndex;
            bool found = false;

            for (uint256 j = 0; j < credIds.length; j++) {
                if (credIds[j] == credentialId) {
                    credIndex = j;
                    found = true;
                    break;
                }
            }

            // Skip if credential not found
            if (!found) continue;

            // Challenge is the hash to be signed
            bytes memory challenge = bytes.concat(hash);

            // Verify WebAuthn signature
            bool valid = WebAuthn.verify(
                challenge, requireUVs[credIndex], auth, pubKeysX[credIndex], pubKeysY[credIndex]
            );

            if (valid) {
                validCount++;

                // Early return if threshold is met
                if (validCount >= thresholdValue) {
                    return (true, validCount);
                }
            }
        }

        return (true, validCount);
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the type of the module
    /// @dev Implements interface to indicate validator capabilities
    /// @param typeID Type identifier to check
    /// @return bool True if this module supports the specified type
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /// @notice Returns the name of the module
    /// @dev Provides a human-readable identifier for the module
    /// @return string Module name
    function name() external pure virtual returns (string memory) {
        return "WebAuthnValidator";
    }

    /// @notice Returns the version of the module
    /// @dev Provides version information for compatibility checks
    /// @return string Semantic version of the module
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}
