// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { ERC7579ExecutorBase, ERC7579FallbackBase } from "modulekit/Modules.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { FlashLoanType, IERC3156FlashBorrower, IERC3156FlashLender } from "modulekit/Interfaces.sol";
import { SentinelListLib } from "sentinellist/SentinelList.sol";
import { Execution } from "modulekit/external/ERC7579.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { HashLib } from "./lib/HashLib.sol";

/**
 * @title FlashloanCallback
 * @dev A base for flashloan callback modules
 * @author Rhinestone
 */
abstract contract FlashloanCallback is
    IERC3156FlashBorrower,
    ERC7579FallbackBase,
    ERC7579ExecutorBase,
    EIP712
{
    using SignatureCheckerLib for address;
    using HashLib for *;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    error TokenGatedTxFailed();
    error Unauthorized();

    mapping(address account => mapping(address borrower => uint256 nonces)) public nonce;

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Called when the module is installed on a smart account
     *
     * @param data The data passed during installation
     */
    function onInstall(bytes calldata data) external virtual;

    /**
     * Called when the module is uninstalled from a smart account
     *
     * @param data The data passed during uninstallation
     */
    function onUninstall(bytes calldata data) external virtual;

    /**
     * Check if the module is initialized on a smart account
     *
     * @param smartAccount The smart account address
     *
     * @return True if the module is initialized
     */
    function isInitialized(address smartAccount) external view virtual returns (bool);

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Check if the callback sender is allowed
     */
    modifier onlyAllowedCallbackSender() {
        if (!_isAllowedCallbackSender()) revert Unauthorized();
        _;
    }

    /**
     * Check if the callback sender is allowed
     */
    function _isAllowedCallbackSender() internal view virtual returns (bool);

    /**
     * Called to execute the flashloan
     * @dev token / amount / fee is not necessary here, token will get paid back in batched exec
     *
     * @param borrower The borrower address
     * @param data The data passed during flashloan
     *
     * @return The hash of the flashloan transaction
     */
    function onFlashLoan(
        address borrower,
        address token,
        uint256 amount,
        uint256, /*fee*/
        bytes calldata data
    )
        external
        onlyAllowedCallbackSender
        returns (bytes32)
    {
        // decode the data
        (FlashLoanType flashLoanType, bytes memory signature, Execution[] memory executions) =
            abi.decode(data, (FlashLoanType, bytes, Execution[]));
        // get the hash
        uint256 currentNonce = nonce[msg.sender][borrower]++;
        bytes32 hash = _hashTypedData(
            HashLib.hashFlashloanExec({
                borrower: borrower,
                lender: msg.sender,
                flashLoanType: flashLoanType,
                token: token,
                amount: amount,
                executions: executions,
                nonce: currentNonce
            })
        );
        // check the signature
        bool validSig = address(msg.sender).isValidSignatureNow(hash, signature);
        // if the signature is invalid, revert
        if (!validSig) revert TokenGatedTxFailed();
        // execute the flashloan

        _execute(executions);
        _execute(
            address(token), 0, abi.encodeWithSignature("approve(address,uint256)", borrower, amount)
        );

        // return the hash
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Returns the version of the module
     *
     * @return version of the module
     */
    function version() public pure virtual returns (string memory) {
        return "1.0.0";
    }

    /**
     * Returns the name of the module
     *
     * @return name of the module
     */
    function name() public pure virtual returns (string memory) {
        return "FlashloanCallback";
    }

    /**
     * Returns the type of the module
     *
     * @param typeID type of the module
     *
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure virtual override returns (bool) {
        return typeID == TYPE_EXECUTOR || typeID == TYPE_FALLBACK;
    }

    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory _name, string memory _version)
    {
        _name = name();
        _version = version();
    }
}
