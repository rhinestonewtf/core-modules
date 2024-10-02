import { ISwapRouter } from "modulekit/integrations/interfaces/uniswap/v3/ISwapRouter.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Execution } from "modulekit/Accounts.sol";

import { IUniswapV3Pool } from "modulekit/integrations/interfaces/uniswap/v3/IUniswapV3Pool.sol";
import { IUniswapV3Factory } from
    "modulekit/integrations/interfaces/uniswap/v3/IUniswapV3Factory.sol";

contract UniswapIntegrationHelper {
    // rm

    function sqrtPriceX96toPriceRatio(uint160 sqrtPriceX96)
        public
        pure
        returns (uint256 priceRatio)
    {
        uint256 decodedSqrtPrice = (sqrtPriceX96 * 10 ** 9) / (2 ** 96);
        priceRatio = decodedSqrtPrice * decodedSqrtPrice;
    }

    // rm
    function priceRatioToPrice(
        uint256 priceRatio,
        address poolAddress,
        address tokenSwappedFrom
    )
        public
        view
        returns (uint256 price)
    {
        IUniswapV3Pool pool = IUniswapV3Pool(poolAddress);
        address poolToken0 = pool.token0();
        address poolToken1 = pool.token1();
        uint256 token0Decimals = IERC20(poolToken0).decimals();
        uint256 token1Decimals = IERC20(poolToken1).decimals();

        bool swapToken0to1 = (tokenSwappedFrom == poolToken0);

        if (swapToken0to1) {
            price = (10 ** token1Decimals * 10 ** 18) / priceRatio;
        } else {
            price = (priceRatio * 10 ** token0Decimals) / 10 ** 18;
        }
        return price;
    }

    // rm
    function priceRatioToSqrtPriceX96(uint256 priceRatio) public pure returns (uint160) {
        uint256 sqrtPriceRatio = sqrt256(priceRatio);

        uint256 sqrtPriceX96 = (sqrtPriceRatio * 2 ** 96) / 1e9; // Adjust back from the scaling

        return uint160(sqrtPriceX96);
    }

    function sqrt256(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
