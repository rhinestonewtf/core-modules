// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ISwapRouter } from "modulekit/integrations/interfaces/uniswap/v3/ISwapRouter.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Execution, ExecutionLib } from "modulekit/Accounts.sol";

import { IUniswapV3Pool } from "modulekit/integrations/interfaces/uniswap/v3/IUniswapV3Pool.sol";
import { IUniswapV3Factory } from
    "modulekit/integrations/interfaces/uniswap/v3/IUniswapV3Factory.sol";

import { ERC20Integration } from "modulekit/Integrations.sol";

/// @author zeroknots
abstract contract InitializableUniswapV3Integration {
    using ERC20Integration for IERC20;

    error PoolDoesNotExist();
    error InvalidSqrtPriceX96();

    event SwapRouterInitialized(address account, address swaprouter, uint24 fee);

    error Unauthorized();
    error InvalidSwapRouter(address swaprouter);

    mapping(address account => address swaprouter) public _swapRouters;

    function setSwapRouter(address swapRouter) public {
        if (swapRouter == address(0)) {
            revert InvalidSwapRouter(swapRouter);
        }
        _swapRouters[msg.sender] = swapRouter;
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
        uint256 amountOutMinimum,
        uint24 fee
    )
        internal
        view
        returns (Execution[] memory exec)
    {
        exec = new Execution[](3);
        (exec[0], exec[1]) =
            ERC20Integration.safeApprove(tokenIn, _swapRouters[smartAccount], amountIn);
        exec[2] = _swapExactInputSingle(
            smartAccount, tokenIn, tokenOut, amountIn, sqrtPriceLimitX96, amountOutMinimum, fee
        );
    }

    function _swapExactInputSingle(
        address smartAccount,
        IERC20 tokenIn,
        IERC20 tokenOut,
        uint256 amountIn,
        uint160 sqrtPriceLimitX96,
        uint256 amountOutMinimum,
        uint24 fee
    )
        internal
        view
        returns (Execution memory exec)
    {
        if (sqrtPriceLimitX96 == 0) revert InvalidSqrtPriceX96();
        exec = Execution({
            target: _swapRouters[smartAccount],
            value: 0,
            callData: abi.encodeCall(
                ISwapRouter.exactInputSingle,
                (
                    ISwapRouter.ExactInputSingleParams({
                        tokenIn: address(tokenIn),
                        tokenOut: address(tokenOut),
                        fee: fee,
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
        uint256 amountInMaximum,
        uint24 fee
    )
        internal
        view
        returns (Execution memory exec)
    {
        if (sqrtPriceLimitX96 == 0) revert InvalidSqrtPriceX96();
        exec = Execution({
            target: _swapRouters[smartAccount],
            value: 0,
            callData: abi.encodeCall(
                ISwapRouter.exactOutputSingle,
                (
                    ISwapRouter.ExactOutputSingleParams({
                        tokenIn: address(tokenIn),
                        tokenOut: address(tokenOut),
                        fee: fee,
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

    function getSqrtPriceX96(address poolAddress) public view returns (uint160 sqrtPriceX96) {
        IUniswapV3Pool pool = IUniswapV3Pool(poolAddress);
        IUniswapV3Pool.Slot0 memory slot0 = pool.slot0();
        sqrtPriceX96 = slot0.sqrtPriceX96;
        return sqrtPriceX96;
    }

    function checkTokenOrder(
        address tokenSwappedFrom,
        address poolAddress
    )
        public
        view
        returns (bool swapToken0to1)
    {
        address poolToken0 = IUniswapV3Pool(poolAddress).token0();
        swapToken0to1 = (tokenSwappedFrom == poolToken0);
        return swapToken0to1;
    }

    function getPoolAddress(
        address factoryAddress,
        address token0,
        address token1,
        uint24 fee
    )
        public
        view
        returns (address poolAddress)
    {
        IUniswapV3Factory factory = IUniswapV3Factory(factoryAddress);
        poolAddress = factory.getPool(token0, token1, fee);
        if (poolAddress == address(0)) {
            revert PoolDoesNotExist();
        }
        return poolAddress;
    }
}
