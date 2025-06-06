// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { IERC7579Account } from "modulekit/accounts/common/interfaces/IERC7579Account.sol";

import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { ExecutionHelper, Execution } from "modulekit/accounts/erc7579/helpers/ExecutionHelper.sol";
import { ExecutionLib } from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";
import {
    ModeLib,
    ModeCode,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE
} from "modulekit/accounts/common/lib/ModeLib.sol";

contract MockAccount is IERC7579Account, ExecutionHelper {
    using ExecutionLib for bytes;
    using ModeLib for ModeCode;

    error UnsupportedCallType(CallType callType);

    function execute(ModeCode mode, bytes calldata executionCalldata) external payable { }

    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        payable
        returns (bytes[] memory returnData)
    {
        CallType callType = mode.getCallType();

        if (callType == CALLTYPE_BATCH) {
            Execution[] calldata executions = executionCalldata.decodeBatch();
            returnData = _execute(executions);
        } else if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata callData) =
                executionCalldata.decodeSingle();
            returnData = new bytes[](1);
            returnData[0] = _execute(target, value, callData);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata data) external view returns (bytes4) { }
    function installModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    )
        external
        payable
    { }

    function uninstallModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata deInitData
    )
        external
        payable
    { }
    function supportsExecutionMode(ModeCode encodedMode) external view returns (bool) { }
    function supportsModule(uint256 moduleTypeId) external view returns (bool) { }

    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    )
        external
        view
        returns (bool)
    {
        if (module == address(0x420)) {
            return false;
        }
        return true;
    }

    function accountId() external view returns (string memory accountImplementationId) { }
}
