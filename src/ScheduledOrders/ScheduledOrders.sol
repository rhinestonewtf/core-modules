// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { IERC7579Account, Execution } from "modulekit/Accounts.sol";
import { SchedulingBase } from "modulekit/Modules.sol";
import { InitializableUniswapV3Integration } from "../utils/uniswap/UniswapIntegration.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

/**
 * @title ScheduledOrders
 * @dev Module that allows users to schedule swaps to be executed at a later time
 * @author Rhinestone
 */
contract ScheduledOrders is SchedulingBase, InitializableUniswapV3Integration {
    error InvalidSqrtPriceLimitX96();

    function onInstall(bytes calldata data) external override {
        address swapRouter = address(bytes20(data[:20]));
        bytes calldata scheduledData = data[20:];

        setSwapRouter(swapRouter);

        _onInstall(scheduledData);
    }

    function onUninstall(bytes calldata) external override {
        _deinitSwapRouter();
        _onUninstall();
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Executes a scheduled swap order
     *
     * @param jobId unique identifier for the job
     */
    function executeOrder(
        uint256 jobId,
        uint160 sqrtPriceLimitX96,
        uint256 amountOutMinimum,
        uint24 fee
    )
        external
        canExecute(jobId)
    {
        // get the execution config
        ExecutionConfig storage executionConfig = executionLog[msg.sender][jobId];

        // decode from executionData: tokenIn, tokenOut, amountIn and sqrtPriceLimitX96
        (address tokenIn, address tokenOut, uint256 amountIn) =
            abi.decode(executionConfig.executionData, (address, address, uint256));

        // approve and swap
        Execution[] memory executions = _approveAndSwap({
            smartAccount: msg.sender,
            tokenIn: IERC20(tokenIn),
            tokenOut: IERC20(tokenOut),
            amountIn: amountIn,
            sqrtPriceLimitX96: sqrtPriceLimitX96,
            amountOutMinimum: amountOutMinimum,
            fee: fee
        });

        // update the execution config
        executionConfig.lastExecutionTime = uint48(block.timestamp);
        executionConfig.numberOfExecutionsCompleted += 1;

        // execute the swap
        IERC7579Account(msg.sender).executeFromExecutor(
            ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(executions)
        );

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
        return "ScheduledOrders";
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
