// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { AutoSavings } from "src/AutoSavings/AutoSavings.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { UD2x18, ud2x18, intoUint256, intoUD60x18 } from "@prb/math/UD2x18.sol";
import { ud } from "@prb/math/UD60x18.sol";
import { MockERC20 } from "solmate/test/utils/mocks/MockERC20.sol";
import { MockERC4626 } from "solmate/test/utils/mocks/MockERC4626.sol";
import { MockAccount } from "test/mocks/MockAccount.sol";
import { MockUniswap } from "modulekit/integrations/uniswap/MockUniswap.sol";
import { SWAPROUTER_ADDRESS } from "modulekit/integrations/uniswap/helpers/MainnetAddresses.sol";
import { SENTINEL } from "sentinellist/SentinelList.sol";

address constant SWAP_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
uint24 constant FEE = 3000;

contract AutoSavingsConcreteTest is BaseTest {
    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    AutoSavings internal executor;

    MockAccount internal account;
    MockERC20 internal token1;
    MockERC20 internal token2;
    MockERC4626 internal vault1;
    MockERC4626 internal vault2;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    address[] _tokens;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        BaseTest.setUp();
        executor = new AutoSavings();
        account = new MockAccount();

        token1 = new MockERC20("USDC", "USDC", 18);
        vm.label(address(token1), "USDC");
        token1.mint(address(account), ud(1_000_000e18).intoUint256());

        token2 = new MockERC20("wETH", "wETH", 18);
        vm.label(address(token2), "wETH");
        token2.mint(address(account), ud(1_000_000e18).intoUint256());

        vault1 = new MockERC4626(token1, "vUSDC", "vUSDC");
        vault2 = new MockERC4626(token2, "vwETH", "vwETH");

        _tokens = new address[](2);
        _tokens[0] = address(token1);
        _tokens[1] = address(token2);

        // set up mock uniswap
        MockUniswap _mockUniswap = new MockUniswap();
        vm.etch(SWAPROUTER_ADDRESS, address(_mockUniswap).code);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     UTILS
    //////////////////////////////////////////////////////////////////////////*/

    function getConfigs() public view returns (AutoSavings.Config[] memory _configs) {
        _configs = new AutoSavings.Config[](2);
        _configs[0] = AutoSavings.Config(ud2x18(0.01e18), address(vault1));
        _configs[1] = AutoSavings.Config(ud2x18(0.01e18), address(vault2));
    }

    function formatConfigs(
        address[] memory tokens,
        AutoSavings.Config[] memory _configs
    )
        public
        pure
        returns (AutoSavings.ConfigWithToken[] memory _configsWithToken)
    {
        _configsWithToken = new AutoSavings.ConfigWithToken[](_configs.length);

        for (uint256 i; i < _configs.length; i++) {
            _configsWithToken[i] = AutoSavings.ConfigWithToken({
                token: tokens[i],
                percentage: _configs[i].percentage,
                vault: _configs[i].vault
            });
        }
    }

    function installFromAccount(address _account) public {
        AutoSavings.Config[] memory _configs = getConfigs();
        AutoSavings.ConfigWithToken[] memory _configsWithToken = formatConfigs(_tokens, _configs);
        bytes memory data = abi.encode(SWAP_ROUTER, _configsWithToken);

        vm.prank(_account);
        executor.onInstall(data);

        for (uint256 i; i < _tokens.length; i++) {
            (UD2x18 _percentage, address _vault) = executor.config(_account, _tokens[i]);
            assertEq(_percentage.intoUint256(), _configs[i].percentage.intoUint256());
            assertEq(_vault, _configs[i].vault);
        }

        address[] memory tokens = executor.getTokens(_account);
        assertEq(tokens.length, _tokens.length);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstallRevertWhen_ModuleIsIntialized() public {
        // it should revert
        AutoSavings.Config[] memory _configs = getConfigs();
        AutoSavings.ConfigWithToken[] memory _configsWithToken = formatConfigs(_tokens, _configs);
        bytes memory data = abi.encode(SWAP_ROUTER, _configsWithToken);
        executor.onInstall(data);

        vm.expectRevert();
        executor.onInstall(data);
    }

    function test_OnInstallRevertWhen_TokensIsGreaterThanMax() public whenModuleIsNotIntialized {
        // it should revert
        uint256 maxTokens = 100;

        AutoSavings.ConfigWithToken[] memory configs =
            new AutoSavings.ConfigWithToken[](maxTokens + 1);
        for (uint256 i = 0; i < maxTokens; i++) {
            configs[i] = AutoSavings.ConfigWithToken({
                token: makeAddr(vm.toString(i)),
                percentage: ud2x18(0.01e18),
                vault: address(0)
            });
        }

        bytes memory data = abi.encode(SWAP_ROUTER, configs);

        vm.expectRevert(abi.encodeWithSelector(AutoSavings.TooManyTokens.selector));
        executor.onInstall(data);
    }

    function test_OnInstallWhenSqrtPriceLimitX96IsNot0()
        public
        whenModuleIsNotIntialized
        whenTokensIsNotGreaterThanMax
    {
        // it should set the configs for each token
        // it should add all tokens
        AutoSavings.Config[] memory _configs = getConfigs();
        AutoSavings.ConfigWithToken[] memory _configsWithToken = formatConfigs(_tokens, _configs);
        bytes memory data = abi.encode(SWAP_ROUTER, _configsWithToken);

        executor.onInstall(data);

        for (uint256 i; i < _tokens.length; i++) {
            (UD2x18 _percentage, address _vault) = executor.config(address(this), _tokens[i]);
            assertEq(_percentage.intoUint256(), _configs[i].percentage.intoUint256());
            assertEq(_vault, _configs[i].vault);
        }

        address[] memory tokens = executor.getTokens(address(this));
        assertEq(tokens.length, _tokens.length);
    }

    function test_OnUninstallShouldRemoveAllTheConfigs() public {
        // it should remove all the configs
        test_OnInstallWhenSqrtPriceLimitX96IsNot0();

        executor.onUninstall("");

        for (uint256 i; i < _tokens.length; i++) {
            (UD2x18 _percentage, address _vault) = executor.config(address(this), _tokens[i]);
            assertEq(_percentage.intoUint256(), 0);
            assertEq(_vault, address(0));
        }
    }

    function test_OnUninstallShouldRemoveAllStoredTokens() public {
        // it should remove all stored tokens
        test_OnInstallWhenSqrtPriceLimitX96IsNot0();

        executor.onUninstall("");

        address[] memory tokens = executor.getTokens(address(this));
        assertEq(tokens.length, 0);
    }

    function test_IsInitializedWhenModuleIsNotIntialized() public view {
        // it should return false
        bool isInitialized = executor.isInitialized(address(this));
        assertFalse(isInitialized);
    }

    function test_IsInitializedWhenModuleIsIntialized() public {
        // it should return true
        test_OnInstallWhenSqrtPriceLimitX96IsNot0();

        bool isInitialized = executor.isInitialized(address(this));
        assertTrue(isInitialized);
    }

    function test_SetConfigRevertWhen_ModuleIsNotIntialized() public {
        // it should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        executor.setConfig(_tokens[0], getConfigs()[0]);
    }

    function test_SetConfigWhenSqrtPriceLimitX96IsNot0() public whenModuleIsIntialized {
        // it should set the config for the token
        test_OnInstallWhenSqrtPriceLimitX96IsNot0();

        address token = address(2);
        AutoSavings.Config memory config = AutoSavings.Config(ud2x18(10), address(1));

        executor.setConfig(token, config);

        (UD2x18 _percentage, address _vault) = executor.config(address(this), token);
        assertEq(_percentage.intoUint256(), config.percentage.intoUint256());
        assertEq(_vault, config.vault);
    }

    function test_DeleteConfigRevertWhen_ModuleIsNotIntialized() public {
        // it should revert
        vm.expectRevert();
        executor.deleteConfig(SENTINEL, _tokens[1]);
    }

    function test_DeleteConfigWhenModuleIsIntialized() public {
        // it should remove the token from the stored tokens
        // it should delete the config for the token
        test_OnInstallWhenSqrtPriceLimitX96IsNot0();

        executor.deleteConfig(SENTINEL, _tokens[1]);

        (UD2x18 _percentage, address _vault) = executor.config(address(this), _tokens[1]);
        assertEq(_percentage.intoUint256(), 0);
        assertEq(_vault, address(0));
    }

    function test_CalcDepositAmountShouldReturnTheDepositAmount() public view {
        // it should return the deposit amount
        uint256 amountReceived = ud(100e18).intoUint256();
        UD2x18 percentage = ud2x18(0.01e18);

        uint256 depositAmount = executor.calcDepositAmount(amountReceived, percentage);

        assertEq(depositAmount, ud(amountReceived).mul(percentage.intoUD60x18()).intoUint256());
    }

    function test_AutoSaveRevertWhen_ModuleIsNotIntialized() public {
        // it should revert
        address token = _tokens[0];
        uint256 amountReceived = 100;

        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        executor.autoSave(token, amountReceived, 1, 0, FEE);
    }

    function test_AutoSaveWhenTheTokenProvidedIsNotTheUnderlyingAsset()
        public
        whenModuleIsIntialized
    {
        // it should execute a swap to the underlying asset
        // it should deposit the amount to the vault
        // it should emit an AutoSaveExecuted event
        installFromAccount(address(account));
        AutoSavings.Config memory config = AutoSavings.Config(ud2x18(0.01e18), address(vault2));

        vm.prank(address(account));
        executor.setConfig(address(token1), config);

        uint256 amountReceived = 100;
        uint256 amountSaved = executor.calcDepositAmount(amountReceived, config.percentage);

        vm.expectEmit(true, true, true, true, address(executor));
        emit AutoSavings.AutoSaveExecuted({
            smartAccount: address(account),
            token: address(token1),
            amountIn: amountSaved
        });

        vm.prank(address(account));
        executor.autoSave(address(token1), amountReceived, 1, 0, FEE);

        executor.config(address(account), address(token1));

        uint256 assetsAfter = vault2.totalAssets();
        assertEq(assetsAfter, amountSaved);
    }

    function test_AutoSaveWhenTheTokenProvidedIsTheUnderlyingAsset()
        public
        whenModuleIsIntialized
    {
        // it should deposit the amount to the vault
        // it should emit an AutoSaveExecuted event
        installFromAccount(address(account));

        uint256 assetsBefore = vault1.totalAssets();

        address token = _tokens[0];
        uint256 amountReceived = ud(100e18).intoUint256();

        vm.expectEmit(true, true, true, true, address(executor));
        emit AutoSavings.AutoSaveExecuted({
            smartAccount: address(account),
            token: token,
            amountIn: ud(amountReceived).mul(ud(0.01e18)).intoUint256()
        });

        vm.prank(address(account));
        executor.autoSave(token, amountReceived, 1, 0, FEE);

        (UD2x18 percentage,) = executor.config(address(account), token);

        uint256 assetsAfter = vault1.totalAssets();
        assertEq(
            assetsAfter,
            assetsBefore + (ud(amountReceived).mul(percentage.intoUD60x18())).intoUint256()
        );
    }

    function test_NameShouldReturnAutoSavings() public view {
        // it should return AutoSavings
        string memory name = executor.name();
        assertEq(name, "AutoSavings");
    }

    function test_VersionShouldReturn100() public view {
        // it should return 1.0.0
        string memory version = executor.version();
        assertEq(version, "1.0.0");
    }

    function test_IsModuleTypeWhenTypeIDIs2() public view {
        // it should return true
        bool isModuleType = executor.isModuleType(2);
        assertTrue(isModuleType);
    }

    function test_IsModuleTypeWhenTypeIDIsNot2() public view {
        // it should return false
        bool isModuleType = executor.isModuleType(1);
        assertFalse(isModuleType);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    MODIFIERS
    //////////////////////////////////////////////////////////////////////////*/

    modifier whenTokensIsNotGreaterThanMax() {
        _;
    }

    modifier whenModuleIsNotIntialized() {
        _;
    }

    modifier whenModuleIsIntialized() {
        _;
    }
}
