// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { ERC7579FallbackBase } from "modulekit/Modules.sol";

import { IERC165 } from "forge-std/interfaces/IERC165.sol";
import { LinkedBytes32Lib } from "@rhinestone/sentinellist/src/SentinelListBytes32.sol";

interface IERC7579Defaults {
    function foobar() external;
}

contract SupportsInterface is ERC7579FallbackBase, IERC165 {
    using LinkedBytes32Lib for LinkedBytes32Lib.LinkedBytes32;

    mapping(address account => LinkedBytes32Lib.LinkedBytes32 list) internal $allInterfaces;

    error Unauthorized();

    /**
     * Called when the module is installed on a smart account
     *
     * @param data The data passed during installation
     */
    function onInstall(bytes calldata data) external virtual {
        bytes4[] memory ids = abi.decode(data, (bytes4[]));

        LinkedBytes32Lib.LinkedBytes32 storage $list = $allInterfaces[msg.sender];
        $list.init();

        for (uint256 i; i < ids.length; i++) {
            bytes4 _id = ids[i];
            bytes32 newId;
            assembly {
                newId := _id
            }
            $list.push(newId);
        }
    }

    function onUninstall(bytes calldata) external virtual {
        $allInterfaces[msg.sender].popAll();
    }

    function setInterfaceId(bytes4 supportedInterface) external {
        if (_msgSender() != msg.sender) revert Unauthorized();

        bytes32 _id;
        assembly {
            _id := supportedInterface
        }
        $allInterfaces[msg.sender].push(_id);
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        if (interfaceID == type(IERC7579Defaults).interfaceId) {
            return true;
        }

        bytes32 _id;
        assembly {
            _id := interfaceID
        }
        return $allInterfaces[msg.sender].contains(_id);
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
