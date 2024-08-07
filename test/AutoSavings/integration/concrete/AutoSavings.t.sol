// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseIntegrationTest, ModuleKitHelpers, ModuleKitUserOp } from "test/BaseIntegration.t.sol";
import { AutoSavings } from "src/AutoSavings/AutoSavings.sol";
import { MODULE_TYPE_EXECUTOR } from "modulekit/external/ERC7579.sol";
import { MockERC4626, ERC20 } from "solmate/test/utils/mocks/MockERC4626.sol";
import { SENTINEL } from "sentinellist/SentinelList.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { UD2x18, ud2x18, intoUint256, intoUD60x18 } from "@prb/math/UD2x18.sol";

address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

contract AutoSavingsIntegrationTest is BaseIntegrationTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    AutoSavings internal executor;

    MockERC4626 internal vault1;
    MockERC4626 internal vault2;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    address[] _tokens;

    IERC20 usdc = IERC20(USDC);
    IERC20 weth = IERC20(WETH);

    uint256 mainnetFork;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        string memory mainnetUrl = vm.rpcUrl("mainnet");
        mainnetFork = vm.createFork(mainnetUrl);
        vm.selectFork(mainnetFork);
        vm.rollFork(19_274_877);

        vm.allowCheatcodes(0x864B12d347dafD27Ce36eD763a3D6764F182F835);

        BaseIntegrationTest.setUp();

        executor = new AutoSavings();

        vm.label(address(usdc), "USDC");
        vm.label(address(weth), "WETH");

        deal(address(usdc), instance.account, 1_000_000);
        deal(address(weth), instance.account, 1_000_000);

        vault1 = new MockERC4626(ERC20(address(usdc)), "vUSDC", "vUSDC");
        vault2 = new MockERC4626(ERC20(address(weth)), "vwETH", "vwETH");

        _tokens = new address[](2);
        _tokens[0] = address(usdc);
        _tokens[1] = address(weth);

        AutoSavings.Config[] memory _configs = getConfigs();
        AutoSavings.ConfigWithToken[] memory _configsWithToken = formatConfigs(_tokens, _configs);
        bytes memory data = abi.encode(_configsWithToken);

        instance.installModule({
            moduleTypeId: MODULE_TYPE_EXECUTOR,
            module: address(executor),
            data: data
        });
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     UTILS
    //////////////////////////////////////////////////////////////////////////*/

    function getConfigs() public returns (AutoSavings.Config[] memory _configs) {
        _configs = new AutoSavings.Config[](2);
        _configs[0] = AutoSavings.Config(ud2x18(0.01e18), address(vault1), 10);
        _configs[1] = AutoSavings.Config(ud2x18(0.01e18), address(vault2), 10);
    }

    function formatConfigs(
        address[] memory _tokens,
        AutoSavings.Config[] memory _configs
    )
        public
        returns (AutoSavings.ConfigWithToken[] memory _configsWithToken)
    {
        _configsWithToken = new AutoSavings.ConfigWithToken[](_configs.length);

        for (uint256 i; i < _configs.length; i++) {
            _configsWithToken[i] = AutoSavings.ConfigWithToken({
                token: _tokens[i],
                percentage: _configs[i].percentage,
                vault: _configs[i].vault,
                sqrtPriceLimitX96: _configs[i].sqrtPriceLimitX96
            });
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstallSetsConfigAndTokens() public {
        // it should set the config and tokens of the account
        bool isInitialized = executor.isInitialized(address(instance.account));
        assertTrue(isInitialized);

        AutoSavings.Config[] memory _configs = getConfigs();

        for (uint256 i; i < _tokens.length; i++) {
            (UD2x18 _percentage, address _vault, uint128 _sqrtPriceLimitX96) =
                executor.config(address(instance.account), _tokens[i]);
            assertEq(_percentage.intoUint256(), _configs[i].percentage.intoUint256());
            assertEq(_vault, _configs[i].vault);
            assertEq(_sqrtPriceLimitX96, _configs[i].sqrtPriceLimitX96);
        }

        address[] memory tokens = executor.getTokens(address(instance.account));
        assertEq(tokens.length, _tokens.length);
    }

    function test_OnUninstallRemovesConfigAndTokens() public {
        // it should remove the config and tokens of the account
        instance.uninstallModule({
            moduleTypeId: MODULE_TYPE_EXECUTOR,
            module: address(executor),
            data: ""
        });

        bool isInitialized = executor.isInitialized(address(instance.account));
        assertFalse(isInitialized);

        for (uint256 i; i < _tokens.length; i++) {
            (UD2x18 _percentage, address _vault, uint128 _sqrtPriceLimitX96) =
                executor.config(address(instance.account), _tokens[i]);
            assertEq(_percentage.intoUint256(), 0);
            assertEq(_vault, address(0));
            assertEq(_sqrtPriceLimitX96, 0);
        }

        address[] memory tokens = executor.getTokens(address(instance.account));
        assertEq(tokens.length, 0);
    }

    function test_SetConfig() public {
        // it should add a config and token
        address token = address(2);
        AutoSavings.Config memory config = AutoSavings.Config(ud2x18(10), address(1), 100);

        instance.getExecOps({
            target: address(executor),
            value: 0,
            callData: abi.encodeCall(AutoSavings.setConfig, (token, config)),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        (UD2x18 _percentage, address _vault, uint128 _sqrtPriceLimitX96) =
            executor.config(address(instance.account), token);
        assertEq(_percentage.intoUint256(), config.percentage.intoUint256());
        assertEq(_vault, config.vault);
        assertEq(_sqrtPriceLimitX96, config.sqrtPriceLimitX96);
    }

    function test_DeleteConfig() public {
        // it should delete a config and token
        AutoSavings.Config[] memory _configs = getConfigs();

        (UD2x18 _percentage, address _vault, uint128 _sqrtPriceLimitX96) =
            executor.config(address(instance.account), _tokens[1]);
        assertEq(_percentage.intoUint256(), _configs[1].percentage.intoUint256());
        assertEq(_vault, _configs[1].vault);
        assertEq(_sqrtPriceLimitX96, _configs[1].sqrtPriceLimitX96);

        instance.getExecOps({
            target: address(executor),
            value: 0,
            callData: abi.encodeCall(AutoSavings.deleteConfig, (SENTINEL, _tokens[1])),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        (_percentage, _vault, _sqrtPriceLimitX96) =
            executor.config(address(instance.account), _tokens[1]);
        assertEq(_percentage.intoUint256(), 0);
        assertEq(_vault, address(0));
        assertEq(_sqrtPriceLimitX96, 0);
    }

    function test_AutoSave_WithUnderlyingToken() public {
        // it should deposit the underlying token into the vault
        uint256 amountReceived = 100;
        uint256 prevBalance = usdc.balanceOf(address(vault1));
        uint256 prevBalanceAccount = usdc.balanceOf(address(instance.account));
        uint256 assetsBefore = vault1.totalAssets();

        instance.getExecOps({
            target: address(executor),
            value: 0,
            callData: abi.encodeCall(AutoSavings.autoSave, (address(usdc), amountReceived)),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        (UD2x18 _percentage,,) = executor.config(address(instance.account), address(usdc));
        uint256 depositAmount = executor.calcDepositAmount(amountReceived, _percentage);

        assertEq(usdc.balanceOf(address(instance.account)), prevBalanceAccount - depositAmount);
        assertEq(usdc.balanceOf(address(vault1)), prevBalance + depositAmount);

        uint256 assetsAfter = vault1.totalAssets();
        assertGt(assetsAfter, assetsBefore);
    }

    function test_AutoSave_WithNonUnderlyingToken() public {
        // it should deposit the underlying token into the vault
        uint128 limit = 100;
        AutoSavings.Config memory config =
            AutoSavings.Config(ud2x18(0.01e18), address(vault2), limit);

        instance.getExecOps({
            target: address(executor),
            value: 0,
            callData: abi.encodeCall(AutoSavings.setConfig, (address(usdc), config)),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        // note: this is a hack to use limit 0 instead of calculating the correct limit for the pair
        bytes32 slot = bytes32(
            uint256(
                keccak256(
                    abi.encode(address(usdc), keccak256(abi.encode(address(instance.account), 0)))
                )
            ) + 1
        );
        bytes32 storedLimit = vm.load(address(executor), slot);
        assertEq(uint256(storedLimit), uint256(limit));
        vm.store(address(executor), slot, bytes32(0));

        uint256 amountReceived = 1000;
        uint256 assetsBefore = vault2.totalAssets();

        instance.getExecOps({
            target: address(executor),
            value: 0,
            callData: abi.encodeCall(AutoSavings.autoSave, (address(usdc), amountReceived)),
            txValidator: address(instance.defaultValidator)
        }).execUserOps();

        uint256 assetsAfter = vault2.totalAssets();
        assertGt(assetsAfter, assetsBefore);
    }
}
