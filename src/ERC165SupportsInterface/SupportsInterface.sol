// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { ERC7579FallbackBase } from "modulekit/Modules.sol";

import { IERC165 } from "forge-std/interfaces/IERC165.sol";

interface IERC7579Defaults {
    function foobar() external;
}

contract SupportsInterface is ERC7579FallbackBase, IERC165 {
    mapping(address account => mapping(bytes4 interfaceID => bool)) internal $accountInterfaces;

    /**
     * Called when the module is installed on a smart account
     *
     * @param data The data passed during installation
     */
    function onInstall(bytes calldata data) external virtual { }

    /**
     * Called when the module is uninstalled from a smart account
     *
     * @param data The data passed during uninstallation
     */
    function onUninstall(bytes calldata data) external virtual { }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        if (interfaceID == type(IERC7579Defaults).interfaceId) {
            return true;
        }
        if ($accountInterfaces[msg.sender][interfaceID]) {
            return true;
        }
    }

    /**
     * Check if the module is initialized on a smart account
     *
     * @param smartAccount The smart account address
     *
     * @return True if the module is initialized
     */
    function isInitialized(address smartAccount) external view virtual returns (bool) { }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Returns the version of the module
     *
     * @return version of the module
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }

    /**
     * Returns the name of the module
     *
     * @return name of the module
     */
    function name() external pure virtual returns (string memory) {
        return "SupportsInterface";
    }

    /**
     * Returns the type of the module
     *
     * @param typeID type of the module
     *
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure virtual override returns (bool) {
        return typeID == TYPE_FALLBACK;
    }
}
