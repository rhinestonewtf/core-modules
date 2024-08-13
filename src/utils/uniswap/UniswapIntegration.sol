// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ISwapRouter } from "modulekit/integrations/interfaces/uniswap/v3/ISwapRouter.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Execution } from "modulekit/Accounts.sol";

import { ERC20Integration } from "modulekit/Integrations.sol";

/// @author zeroknots
abstract contract InitializableUniswapV3Integration {
    using ERC20Integration for IERC20;

    uint24 private constant SWAPROUTER_DEFAULTFEE = 3000;

    error PoolDoesNotExist();

    event SwapRouterInitialized(address swaprouter);

    address private immutable INITIALIZER;
    address public SWAPROUTER_ADDRESS;

    error Unauthorized();
    error InvalidParam(address swaprouter);

    constructor(address initializer) {
        INITIALIZER = initializer;
    }

    function initializeSwapRouter(address swaprouter) public {
        if (msg.sender != INITIALIZER) revert Unauthorized();
        if (SWAPROUTER_ADDRESS != address(0)) revert Unauthorized();
        if (swaprouter == address(0)) revert InvalidParam(swaprouter);
        SWAPROUTER_ADDRESS = swaprouter;
        emit SwapRouterInitialized(swaprouter);
    }

    function _approveAndSwap(
        address smartAccount,
        IERC20 tokenIn,
        IERC20 tokenOut,
        uint256 amountIn,
        uint160 sqrtPriceLimitX96,
        uint256 amountOutMinimum
    )
        internal
        view
        returns (Execution[] memory exec)
    {
        exec = new Execution[](3);
        (exec[0], exec[1]) = ERC20Integration.safeApprove(tokenIn, SWAPROUTER_ADDRESS, amountIn);
        exec[2] = _swapExactInputSingle(
            smartAccount, tokenIn, tokenOut, amountIn, sqrtPriceLimitX96, amountOutMinimum
        );
    }

    function _swapExactInputSingle(
        address smartAccount,
        IERC20 tokenIn,
        IERC20 tokenOut,
        uint256 amountIn,
        uint160 sqrtPriceLimitX96,
        uint256 amountOutMinimum
    )
        internal
        view
        returns (Execution memory exec)
    {
        exec = Execution({
            target: SWAPROUTER_ADDRESS,
            value: 0,
            callData: abi.encodeCall(
                ISwapRouter.exactInputSingle,
                (
                    ISwapRouter.ExactInputSingleParams({
                        tokenIn: address(tokenIn),
                        tokenOut: address(tokenOut),
                        fee: SWAPROUTER_DEFAULTFEE,
                        recipient: smartAccount,
                        deadline: block.timestamp,
                        amountIn: amountIn,
                        amountOutMinimum: amountOutMinimum,
                        sqrtPriceLimitX96: sqrtPriceLimitX96
                    })
                )
            )
        });
    }

    function _swapExactOutputSingle(
        address smartAccount,
        IERC20 tokenIn,
        IERC20 tokenOut,
        uint256 amountOut,
        uint160 sqrtPriceLimitX96,
        uint256 amountInMaximum
    )
        internal
        view
        returns (Execution memory exec)
    {
        exec = Execution({
            target: SWAPROUTER_ADDRESS,
            value: 0,
            callData: abi.encodeCall(
                ISwapRouter.exactOutputSingle,
                (
                    ISwapRouter.ExactOutputSingleParams({
                        tokenIn: address(tokenIn),
                        tokenOut: address(tokenOut),
                        fee: SWAPROUTER_DEFAULTFEE,
                        recipient: smartAccount,
                        deadline: block.timestamp,
                        amountOut: amountOut,
                        amountInMaximum: amountInMaximum,
                        sqrtPriceLimitX96: sqrtPriceLimitX96
                    })
                )
            )
        });
    }
}
