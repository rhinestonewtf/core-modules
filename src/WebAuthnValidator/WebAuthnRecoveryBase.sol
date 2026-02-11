// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/// @title WebAuthnRecoveryBase
/// @notice Abstract recovery mixin for WebAuthn validators with EIP-712 typed data
/// @dev Provides two recovery paths:
///      1. Existing passkey signs an EIP-712 RecoverPasskey message
///      2. Guardian (EIP-1271 smart contract) signs the same EIP-712 message
///      Uses chain-agnostic domain separator with chainId in the struct for cross-chain recovery.
///      chainId = 0 means valid on any chain.
///      Inheriting contract must implement the abstract hooks.
abstract contract WebAuthnRecoveryBase is EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event GuardianSet(address indexed account, address indexed guardian);
    event PasskeyRecoveryExecuted(address indexed account, uint16 indexed newKeyId, uint256 nonce);
    event GuardianRecoveryExecuted(
        address indexed account, address indexed guardian, uint16 indexed newKeyId, uint256 nonce
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error RecoveryExpired();
    error NonceAlreadyUsed();
    error GuardianNotConfigured();
    error InvalidRecoverySignature();
    error InvalidGuardianSignature();
    error InvalidChainId();

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct NewCredential {
        uint16 keyId;
        uint256 pubKeyX;
        uint256 pubKeyY;
        bool requireUV;
    }

    struct RecoveryConfig {
        address guardian;
        mapping(uint256 nonce => bool) nonceUsed;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RECOVER_PASSKEY_TYPEHASH = keccak256(
        "RecoverPasskey(address account,uint256 chainId,uint16 newKeyId,uint256 newPubKeyX,uint256 newPubKeyY,bool newRequireUV,uint256 nonce,uint48 expiry)"
    );

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    mapping(address account => RecoveryConfig) internal _recoveryConfig;

    /*//////////////////////////////////////////////////////////////
                              EIP-712 DOMAIN
    //////////////////////////////////////////////////////////////*/

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "WebAuthnValidator";
        version = "2.0.0";
    }

    /*//////////////////////////////////////////////////////////////
                            ABSTRACT HOOKS
    //////////////////////////////////////////////////////////////*/

    function _validateSignatureWithConfig(
        address account,
        bytes32 digest,
        bytes calldata data
    )
        internal
        view
        virtual
        returns (bool);

    function _addCredentialRecovery(address account, NewCredential calldata cred) internal virtual;

    /*//////////////////////////////////////////////////////////////
                              MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier validRecovery(address account, uint256 chainId, uint256 nonce, uint48 expiry) {
        if (block.timestamp > expiry) revert RecoveryExpired();
        if (_recoveryConfig[account].nonceUsed[nonce]) revert NonceAlreadyUsed();
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();
        _recoveryConfig[account].nonceUsed[nonce] = true;
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function setGuardian(address _guardian) external {
        _recoveryConfig[msg.sender].guardian = _guardian;
        emit GuardianSet(msg.sender, _guardian);
    }

    /*//////////////////////////////////////////////////////////////
                                RECOVERY
    //////////////////////////////////////////////////////////////*/

    function recoverWithPasskey(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry,
        bytes calldata signature
    )
        external
        validRecovery(account, chainId, nonce, expiry)
    {
        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);

        if (!_validateSignatureWithConfig(account, digest, signature)) {
            revert InvalidRecoverySignature();
        }

        _addCredentialRecovery(account, cred);

        emit PasskeyRecoveryExecuted(account, cred.keyId, nonce);
    }

    function recoverWithGuardian(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry,
        bytes calldata guardianSig
    )
        external
        validRecovery(account, chainId, nonce, expiry)
    {
        address _guardian = _recoveryConfig[account].guardian;
        if (_guardian == address(0)) revert GuardianNotConfigured();

        bytes32 digest = getRecoverDigest(account, chainId, cred, nonce, expiry);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(_guardian, digest, guardianSig)) {
            revert InvalidGuardianSignature();
        }

        _addCredentialRecovery(account, cred);

        emit GuardianRecoveryExecuted(account, _guardian, cred.keyId, nonce);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function guardian(address account) external view returns (address) {
        return _recoveryConfig[account].guardian;
    }

    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _recoveryConfig[account].nonceUsed[nonce];
    }

    function getRecoverDigest(
        address account,
        uint256 chainId,
        NewCredential calldata cred,
        uint256 nonce,
        uint48 expiry
    )
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataSansChainId(
            keccak256(
                abi.encode(
                    RECOVER_PASSKEY_TYPEHASH,
                    account,
                    chainId,
                    uint256(cred.keyId),
                    cred.pubKeyX,
                    cred.pubKeyY,
                    cred.requireUV,
                    nonce,
                    uint256(expiry)
                )
            )
        );
    }
}
