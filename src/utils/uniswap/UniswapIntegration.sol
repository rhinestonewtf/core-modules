// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ISwapRouter } from "modulekit/integrations/interfaces/uniswap/v3/ISwapRouter.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Execution } from "modulekit/Accounts.sol";

import { ERC20Integration } from "modulekit/Integrations.sol";

/// @author zeroknots
abstract contract InitializableUniswapV3Integration {
    using ERC20Integration for IERC20;

    error PoolDoesNotExist();

    event SwapRouterInitialized(address account, address swaprouter, uint24 fee);

    error Unauthorized();
    error InvalidSwapRouter(address swaprouter);

    struct SwapRouterConfig {
        address swapRouter;
        uint24 fee; // default should be 3000
    }

    mapping(address account => SwapRouterConfig config) internal _swapRouters;

    function _initSwapRouter(address swapRouter, uint24 fee) internal {
        if (swapRouter == address(0)) {
            revert InvalidSwapRouter(swapRouter);
        }
        _swapRouters[msg.sender] = SwapRouterConfig({ swapRouter: swapRouter, fee: fee });
    }

    function _deinitSwapRouter() internal {
        delete _swapRouters[msg.sender];
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
        SwapRouterConfig memory config = _swapRouters[smartAccount];
        exec = new Execution[](3);
        (exec[0], exec[1]) = ERC20Integration.safeApprove(tokenIn, config.swapRouter, amountIn);
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
        SwapRouterConfig memory config = _swapRouters[smartAccount];
        exec = Execution({
            target: config.swapRouter,
            value: 0,
            callData: abi.encodeCall(
                ISwapRouter.exactInputSingle,
                (
                    ISwapRouter.ExactInputSingleParams({
                        tokenIn: address(tokenIn),
                        tokenOut: address(tokenOut),
                        fee: config.fee,
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
        SwapRouterConfig memory config = _swapRouters[smartAccount];
        exec = Execution({
            target: config.swapRouter,
            value: 0,
            callData: abi.encodeCall(
                ISwapRouter.exactOutputSingle,
                (
                    ISwapRouter.ExactOutputSingleParams({
                        tokenIn: address(tokenIn),
                        tokenOut: address(tokenOut),
                        fee: config.fee,
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
