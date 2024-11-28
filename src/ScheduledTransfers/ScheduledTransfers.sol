// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { IERC7579Account } from "modulekit/Accounts.sol";
import { SchedulingBase } from "modulekit/Modules.sol";
import { ModeLib } from "modulekit/accounts/common/lib/ModeLib.sol";
import { ExecutionLib } from "modulekit/accounts/erc7579/lib/ExecutionLib.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { ERC20Integration } from "modulekit/Integrations.sol";

/**
 * @title ScheduledTransfers
 * @dev Module that allows users to schedule transfers to be executed at a later time
 * @author Rhinestone
 */
contract ScheduledTransfers is SchedulingBase {
    using ERC20Integration for IERC20;

    error ERC20TransferFailed();

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    function onInstall(bytes calldata data) external override {
        _onInstall(data);
    }

    function onUninstall(bytes calldata) external override {
        _onUninstall();
    }

    /**
     * Executes a scheduled transfer order
     *
     * @param jobId unique identifier for the job
     */
    function executeOrder(uint256 jobId) external canExecute(jobId) {
        // get the execution config
        ExecutionConfig storage executionConfig = executionLog[msg.sender][jobId];

        // update the execution config
        executionConfig.lastExecutionTime = uint48(block.timestamp);
        executionConfig.numberOfExecutionsCompleted += 1;

        // decode from executionData: recipient, token and amount
        (address recipient, address token, uint256 amount) =
            abi.decode(executionConfig.executionData, (address, address, uint256));

        if (token == address(0)) {
            // execute native token transfer
            _execute(recipient, amount, "");
        } else {
            IERC20(token).safeTransfer({ to: recipient, amount: amount });
        }

        // emit the ExecutionTriggered event
        emit ExecutionTriggered(msg.sender, jobId);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Returns the name of the module
     *
     * @return name of the module
     */
    function name() external pure virtual returns (string memory) {
        return "ScheduledTransfers";
    }

    /**
     * Returns the version of the module
     *
     * @return version of the module
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}
