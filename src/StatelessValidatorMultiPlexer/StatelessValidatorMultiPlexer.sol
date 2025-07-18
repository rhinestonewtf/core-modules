// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { ERC7579StatelessValidatorBase } from "modulekit/Modules.sol";

// Constants
import { MODULE_TYPE_STATELESS_VALIDATOR } from "modulekit/module-bases/utils/ERC7579Constants.sol";

/**
 * @title StatelessValidatorMultiPlexer
 * @dev A stateless validator multiplexer that allows multiple stateless validators to be used in a
 *      single module.
 * @author highskore
 */
contract StatelessValidatorMultiPlexer is ERC7579StatelessValidatorBase {
    /*//////////////////////////////////////////////////////////////////////////
                                        ERRORS
    //////////////////////////////////////////////////////////////////////////*/

    error MismatchedValidatorsAndDataLength();

    /*//////////////////////////////////////////////////////////////////////////
                                        STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Mapping of smart account address to initialized state
    mapping(address account => bool initialized) public isInitialized;

    /*//////////////////////////////////////////////////////////////////////////
                                      CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Called when the module is installed on a smart account
    function onInstall(bytes calldata) external override { }

    /// @notice Called when the module is uninstalled from a smart account
    function onUninstall(bytes calldata) external override { }

    /// @notice Returns the type of the module
    /// @dev Implements interface to indicate validator capabilities
    /// @param typeID Type identifier to check
    /// @return bool True if this module supports the specified type
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    VALIDATION
    //////////////////////////////////////////////////////////////////////////*/

    /// TODO: Optimize this

    /// @notice Validates a signature with data by multiplexing through stateless validators
    /// @param hash The hash of the data to validate
    /// @param signature The signatures to validate
    /// @param data The data to validate against the signature,
    ///        the data is encoded in the following format:
    ///        abi.encode(address[] validators, bytes[] data)
    /// @return bool True if the signature is valid for all validators
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
        // Decode the signatures array
        bytes[] memory signatures = abi.decode(signature, (bytes[]));

        // Decode the data to get the list of validators and their corresponding data
        (address[] memory validators, bytes[] memory validatorData) =
            abi.decode(data, (address[], bytes[]));

        // Cache the length of the validators array
        uint256 validatorsLength = validators.length;

        // Ensure the number of validators matches the number of data entries
        require(
            ((validatorsLength == validatorData.length) && (validatorsLength == signatures.length)),
            MismatchedValidatorsAndDataLength()
        );

        // Validate each signature with its corresponding data
        for (uint256 i = 0; i < validatorsLength; i++) {
            // Call the validateSignatureWithData function on each validator
            bool validSig = ERC7579StatelessValidatorBase(validators[i]).validateSignatureWithData(
                hash, signatures[i], validatorData[i]
            );
            if (!validSig) {
                return false; // If any validation fails, return false
            }
        }

        return true; // All validations passed
    }
}
