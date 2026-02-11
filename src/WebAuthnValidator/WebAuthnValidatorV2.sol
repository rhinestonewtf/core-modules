// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { ERC7579HybridValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { MerkleProofLib } from "solady/utils/MerkleProofLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { WebAuthn } from "@webauthn/WebAuthn.sol";
import {
    MODULE_TYPE_STATELESS_VALIDATOR as TYPE_STATELESS_VALIDATOR
} from "modulekit/module-bases/utils/ERC7579Constants.sol";
import { WebAuthnRecoveryBase } from "./WebAuthnRecoveryBase.sol";

/// @title WebAuthnValidatorV2
/// @notice WebAuthn validator with merkle tree batch signing support
/// @dev The user signs a merkle root (tree of operation digests) with their passkey.
///      Each operation provides a merkle proof showing its digest is a leaf in the tree.
///      When proofLength = 0, falls back to regular signing (user signs digest directly).
///      Supports multiple passkeys via 2-byte keyIds; any single credential can sign.
///      requireUV is packed into the credential key to avoid a 3rd storage slot.
contract WebAuthnValidatorV2 is ERC7579HybridValidatorBase, WebAuthnRecoveryBase {
    using EnumerableSetLib for EnumerableSetLib.Uint256Set;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @param pubKeyX X coordinate of the P-256 public key
    /// @param pubKeyY Y coordinate of the P-256 public key
    struct WebAuthnCredential {
        uint256 pubKeyX;
        uint256 pubKeyY;
    }

    struct PasskeyCredentials {
        mapping(uint256 credKey => WebAuthnCredential) credentials;
        EnumerableSetLib.Uint256Set enabledCredKeys;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event ModuleInitialized(address indexed account);
    event ModuleUninitialized(address indexed account);
    event CredentialAdded(
        address indexed account, uint16 indexed keyId, bool requireUV, uint256 pubKeyX, uint256 pubKeyY
    );
    event CredentialRemoved(address indexed account, uint16 indexed keyId);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidSignatureData();
    error InvalidMerkleProof();
    error ProofTooLong();
    error InvalidPublicKey();
    error CredentialNotFound(uint16 keyId);
    error CannotRemoveLastCredential();
    error KeyIdAlreadyExists(uint16 keyId);
    error TooManyCredentials();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MAX_MERKLE_DEPTH = 32;
    uint256 constant MAX_CREDENTIALS = 64;
    uint256 private constant _REQUIRE_UV_BIT = 1 << 16;

    bytes32 public constant PASSKEY_DIGEST_TYPEHASH =
        keccak256("PasskeyDigest(bytes32 digest)");

    bytes32 public constant PASSKEY_MULTICHAIN_TYPEHASH =
        keccak256("PasskeyMultichain(bytes32 root)");

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Passkey credentials per account
    /// @dev credKey = uint256(keyId) | (requireUV ? _REQUIRE_UV_BIT : 0)
    mapping(address account => PasskeyCredentials) internal _passkeyCredentials;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Install the module with initial credentials and optional guardian
    /// @param data abi.encode(uint16[] keyIds, WebAuthnCredential[] creds, bool[] requireUVs, address guardian)
    function onInstall(bytes calldata data) external override {
        address account = msg.sender;
        if (isInitialized(account)) revert ModuleAlreadyInitialized(account);

        (
            uint16[] memory keyIds,
            WebAuthnCredential[] memory creds,
            bool[] memory requireUVs,
            address _guardian
        ) = abi.decode(data, (uint16[], WebAuthnCredential[], bool[], address));
        uint256 length = creds.length;
        if (length == 0 || length != keyIds.length || length != requireUVs.length) {
            revert InvalidPublicKey();
        }
        if (length > MAX_CREDENTIALS) revert TooManyCredentials();

        PasskeyCredentials storage pc = _passkeyCredentials[account];
        for (uint256 i; i < length; ++i) {
            if (creds[i].pubKeyX == 0 || creds[i].pubKeyY == 0) revert InvalidPublicKey();
            uint256 ck = _credKey(keyIds[i], requireUVs[i]);
            if (!pc.enabledCredKeys.add(ck)) revert KeyIdAlreadyExists(keyIds[i]);
            pc.credentials[ck] = creds[i];
            emit CredentialAdded(account, keyIds[i], requireUVs[i], creds[i].pubKeyX, creds[i].pubKeyY);
        }

        if (_guardian != address(0)) {
            _recoveryConfig[account].guardian = _guardian;
            emit GuardianSet(account, _guardian);
        }

        emit ModuleInitialized(account);
    }

    /// @notice Uninstall the module, clearing all credentials and guardian
    function onUninstall(bytes calldata) external override {
        address account = msg.sender;
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256[] memory credKeys = pc.enabledCredKeys.values();

        for (uint256 i; i < credKeys.length; ++i) {
            delete pc.credentials[credKeys[i]];
            pc.enabledCredKeys.remove(credKeys[i]);
        }

        delete _recoveryConfig[account].guardian;

        emit ModuleUninitialized(account);
    }

    function isInitialized(address smartAccount) public view returns (bool) {
        return _passkeyCredentials[smartAccount].enabledCredKeys.length() > 0;
    }

    /// @notice Get the number of credentials for an account
    function credentialCount(address account) external view returns (uint256) {
        return _passkeyCredentials[account].enabledCredKeys.length();
    }

    /// @notice Get all enabled credential keys for an account
    /// @dev Each credKey encodes keyId in bits [0:15] and requireUV in bit 16
    function getCredKeys(address account) external view returns (uint256[] memory) {
        return _passkeyCredentials[account].enabledCredKeys.values();
    }

    /// @notice Add a new credential with a specific keyId
    function addCredential(uint16 keyId, uint256 pubKeyX, uint256 pubKeyY, bool requireUV) external {
        _addCredential(msg.sender, keyId, pubKeyX, pubKeyY, requireUV);
    }

    /// @notice Remove a credential by keyId and requireUV
    function removeCredential(uint16 keyId, bool requireUV) external {
        address account = msg.sender;
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();
        if (len == 0) revert NotInitialized(account);
        if (len <= 1) revert CannotRemoveLastCredential();
        uint256 ck = _credKey(keyId, requireUV);
        if (!pc.enabledCredKeys.remove(ck)) revert CredentialNotFound(keyId);
        delete pc.credentials[ck];
        emit CredentialRemoved(account, keyId);
    }

    /// @notice Get credential details
    function getCredential(
        uint16 keyId,
        bool requireUV,
        address account
    )
        external
        view
        returns (uint256 pubKeyX, uint256 pubKeyY)
    {
        uint256 ck = _credKey(keyId, requireUV);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];
        return (cred.pubKeyX, cred.pubKeyY);
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-4337 user operation validation
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        if (_validateSignatureWithConfig(userOp.sender, userOpHash, userOp.signature)) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /// @notice EIP-1271 signature validation
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
        if (_validateSignatureWithConfig(msg.sender, hash, data)) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /// @notice Stateless validation with externally provided credentials
    /// @dev data is tightly packed:
    ///   [0]       proofLength (uint8)
    ///   if proofLength == 0 (regular signing, challenge = hash):
    ///     [1:33]    pubKeyX
    ///     [33:65]   pubKeyY
    ///     [65]      requireUV (uint8)
    ///     [66]      usePrecompile (uint8)
    ///   if proofLength > 0 (merkle proof, challenge = merkleRoot):
    ///     [1:33]    merkleRoot
    ///     [33:65]   pubKeyX
    ///     [65:97]   pubKeyY
    ///     [97]      requireUV (uint8)
    ///     [98]      usePrecompile (uint8)
    ///     [99:99+proofLength*32] proof
    /// signature is packed WebAuthnAuth (see _parseWebAuthnAuth)
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
        if (data.length < 1) revert InvalidSignatureData();
        uint256 proofLength = uint8(data[0]);

        if (proofLength == 0) {
            if (data.length < 67) revert InvalidSignatureData();
            WebAuthn.WebAuthnAuth memory auth = _parseWebAuthnAuth(signature);
            return WebAuthn.verify(
                abi.encode(_passkeyDigest(hash)),
                uint8(data[65]) != 0,
                auth,
                uint256(bytes32(data[1:33])),
                uint256(bytes32(data[33:65])),
                uint8(data[66]) != 0
            );
        }

        // Merkle proof path: challenge = merkleRoot
        if (proofLength > MAX_MERKLE_DEPTH) revert ProofTooLong();
        if (data.length < 99) revert InvalidSignatureData();

        bytes32 merkleRoot = bytes32(data[1:33]);
        uint256 proofEnd = 99 + (proofLength << 5);
        if (data.length < proofEnd) revert InvalidSignatureData();

        {
            bytes32[] calldata proof;
            /// @solidity memory-safe-assembly
            assembly {
                proof.offset := add(data.offset, 99)
                proof.length := proofLength
            }
            if (!MerkleProofLib.verifyCalldata(proof, merkleRoot, hash)) {
                revert InvalidMerkleProof();
            }
        }

        {
            WebAuthn.WebAuthnAuth memory auth = _parseWebAuthnAuth(signature);
            return WebAuthn.verify(
                abi.encode(_passkeyMultichain(merkleRoot)),
                uint8(data[97]) != 0,
                auth,
                uint256(bytes32(data[33:65])),
                uint256(bytes32(data[65:97])),
                uint8(data[98]) != 0
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           RECOVERY HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @dev Add a credential during recovery — called by WebAuthnRecoveryBase
    function _addCredentialRecovery(
        address account,
        NewCredential calldata cred
    )
        internal
        override
    {
        _addCredential(account, cred.keyId, cred.pubKeyX, cred.pubKeyY, cred.requireUV);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute the credential storage key from keyId and requireUV
    /// @dev Packs keyId in bits [0:15] and requireUV in bit 16
    function _credKey(uint16 keyId, bool requireUV) internal pure returns (uint256) {
        return uint256(keyId) | (requireUV ? _REQUIRE_UV_BIT : 0);
    }

    /// @notice Chain-specific EIP-712 challenge for single operation signing
    function _passkeyDigest(bytes32 digest) internal view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(PASSKEY_DIGEST_TYPEHASH, digest)));
    }

    /// @notice Chain-agnostic EIP-712 challenge for merkle batch signing
    function _passkeyMultichain(bytes32 root) internal view returns (bytes32) {
        return _hashTypedDataSansChainId(keccak256(abi.encode(PASSKEY_MULTICHAIN_TYPEHASH, root)));
    }

    /// @notice Compute the passkey challenge for a single operation digest
    function getPasskeyDigest(bytes32 digest) public view returns (bytes32) {
        return _passkeyDigest(digest);
    }

    /// @notice Compute the passkey challenge for a merkle root
    function getPasskeyMultichain(bytes32 root) public view returns (bytes32) {
        return _passkeyMultichain(root);
    }

    /// @notice Add a credential with full validation
    function _addCredential(
        address account,
        uint16 keyId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        bool requireUV
    )
        internal
    {
        if (pubKeyX == 0 || pubKeyY == 0) revert InvalidPublicKey();
        PasskeyCredentials storage pc = _passkeyCredentials[account];
        uint256 len = pc.enabledCredKeys.length();
        if (len == 0) revert NotInitialized(account);
        if (len >= MAX_CREDENTIALS) revert TooManyCredentials();
        uint256 ck = _credKey(keyId, requireUV);
        if (!pc.enabledCredKeys.add(ck)) revert KeyIdAlreadyExists(keyId);
        pc.credentials[ck] = WebAuthnCredential(pubKeyX, pubKeyY);
        emit CredentialAdded(account, keyId, requireUV, pubKeyX, pubKeyY);
    }

    /// @notice Core stateful validation
    /// @dev Packed signature format:
    ///   [0]                            proofLength (uint8)
    ///   if proofLength == 0 (regular signing, challenge = digest):
    ///     [1:3]                        keyId (uint16)
    ///     [3]                          requireUV (uint8)
    ///     [4]                          usePrecompile (uint8)
    ///     [5:]                         packed WebAuthnAuth
    ///   if proofLength > 0 (merkle proof, challenge = merkleRoot):
    ///     [1:33]                       merkleRoot (bytes32)
    ///     [33:33+proofLength*32]       proof
    ///     [proofEnd:proofEnd+2]        keyId (uint16)
    ///     [proofEnd+2]                 requireUV (uint8)
    ///     [proofEnd+3]                 usePrecompile (uint8)
    ///     [proofEnd+4:]                packed WebAuthnAuth
    function _validateSignatureWithConfig(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        override
        returns (bool)
    {
        if (data.length < 5) return false;

        uint256 proofLength = uint8(data[0]);

        if (proofLength == 0) {
            return _validateRegular(account, digest, data);
        }

        return _validateMerkle(account, digest, data, proofLength);
    }

    /// @notice Regular signing path (proofLength=0): challenge = digest
    function _validateRegular(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        uint16 keyId = uint16(bytes2(data[1:3]));
        bool requireUV = uint8(data[3]) != 0;
        bool usePrecompile = uint8(data[4]) != 0;

        uint256 ck = _credKey(keyId, requireUV);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];
        if (cred.pubKeyX == 0) return false;

        WebAuthn.WebAuthnAuth memory auth = _parseWebAuthnAuth(data[5:]);
        return WebAuthn.verify(abi.encode(_passkeyDigest(digest)), requireUV, auth, cred.pubKeyX, cred.pubKeyY, usePrecompile);
    }

    /// @notice Merkle signing path (proofLength>0): challenge = merkleRoot
    function _validateMerkle(
        address account,
        bytes32 digest,
        bytes calldata data,
        uint256 proofLength
    )
        internal
        view
        returns (bool)
    {
        if (proofLength > MAX_MERKLE_DEPTH) return false;

        uint256 proofEnd = 33 + (proofLength << 5);
        if (data.length < proofEnd + 4) return false;

        bytes32 merkleRoot = bytes32(data[1:33]);

        {
            bytes32[] calldata proof;
            /// @solidity memory-safe-assembly
            assembly {
                proof.offset := add(data.offset, 33)
                proof.length := proofLength
            }
            if (!MerkleProofLib.verifyCalldata(proof, merkleRoot, digest)) return false;
        }

        uint16 keyId = uint16(bytes2(data[proofEnd:proofEnd + 2]));
        bool requireUV = uint8(data[proofEnd + 2]) != 0;
        bool usePrecompile = uint8(data[proofEnd + 3]) != 0;

        uint256 ck = _credKey(keyId, requireUV);
        WebAuthnCredential storage cred = _passkeyCredentials[account].credentials[ck];
        if (cred.pubKeyX == 0) return false;

        WebAuthn.WebAuthnAuth memory auth = _parseWebAuthnAuth(data[proofEnd + 4:]);
        return WebAuthn.verify(abi.encode(_passkeyMultichain(merkleRoot)), requireUV, auth, cred.pubKeyX, cred.pubKeyY, usePrecompile);
    }

    /// @notice Parse tightly packed WebAuthnAuth from calldata
    /// @dev Format:
    ///   [0:32]              r (uint256)
    ///   [32:64]             s (uint256)
    ///   [64:66]             challengeIndex (uint16)
    ///   [66:68]             typeIndex (uint16)
    ///   [68:70]             authenticatorDataLen (uint16)
    ///   [70:70+adLen]       authenticatorData
    ///   [70+adLen:]         clientDataJSON (remaining bytes)
    function _parseWebAuthnAuth(bytes calldata raw)
        internal
        pure
        returns (WebAuthn.WebAuthnAuth memory auth)
    {
        if (raw.length < 70) revert InvalidSignatureData();

        uint256 adLen;
        /// @solidity memory-safe-assembly
        assembly {
            let off := raw.offset
            // r and s via direct calldataload
            mstore(add(auth, 0x80), calldataload(off))
            mstore(add(auth, 0xa0), calldataload(add(off, 0x20)))
            // Single calldataload extracts challengeIndex(2) + typeIndex(2) + adLen(2)
            let packed := calldataload(add(off, 0x40))
            mstore(add(auth, 0x40), shr(240, packed))
            mstore(add(auth, 0x60), and(shr(224, packed), 0xffff))
            adLen := and(shr(208, packed), 0xffff)
        }

        if (raw.length < 70 + adLen) revert InvalidSignatureData();

        /// @solidity memory-safe-assembly
        assembly {
            let off := raw.offset
            let cdLen := sub(raw.length, add(70, adLen))
            let fmp := mload(0x40)

            // authenticatorData: [length][data...]
            mstore(fmp, adLen)
            calldatacopy(add(fmp, 0x20), add(off, 70), adLen)
            mstore(auth, fmp)

            let adAlloc := add(0x20, and(add(adLen, 0x1f), not(0x1f)))
            let cdPtr := add(fmp, adAlloc)

            // clientDataJSON: [length][data...]
            mstore(cdPtr, cdLen)
            calldatacopy(add(cdPtr, 0x20), add(off, add(70, adLen)), cdLen)
            mstore(add(auth, 0x20), cdPtr)

            mstore(0x40, add(cdPtr, add(0x20, and(add(cdLen, 0x1f), not(0x1f)))))
        }
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    function name() external pure virtual returns (string memory) {
        return "WebAuthnValidatorV2";
    }

    function version() external pure virtual returns (string memory) {
        return "2.0.0";
    }
}
