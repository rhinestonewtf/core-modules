// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ScheduledOrders, SchedulingBase } from "src/ScheduledOrders/ScheduledOrders.sol";
import { IERC7579Module } from "modulekit/external/ERC7579.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { MockTarget } from "test/mocks/MockTarget.sol";

import { UniswapIntegrationHelper } from "../../../utils/UniswapIntegrationHelper.sol";
address constant SWAP_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
uint24 constant FEE = 3000;

address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

address constant FACTORY_ADDRESS = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

contract ScheduledOrdersTest is BaseTest {
    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    IERC20 usdc = IERC20(USDC);
    IERC20 weth = IERC20(WETH);

    uint256 mainnetFork;
    ScheduledOrders internal executor;
    UniswapIntegrationHelper uniswapHelper;
    MockTarget internal target;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        string memory mainnetUrl = vm.rpcUrl("mainnet");
        mainnetFork = vm.createFork(mainnetUrl);
        vm.selectFork(mainnetFork);
        vm.rollFork(19_274_877);

        vm.allowCheatcodes(0x864B12d347dafD27Ce36eD763a3D6764F182F835);
        BaseTest.setUp();

        executor = new ScheduledOrders();
        uniswapHelper = new UniswapIntegrationHelper();
        target = new MockTarget();

        vm.warp(1_713_357_071);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      UTILS
    //////////////////////////////////////////////////////////////////////////*/

    function checkExecutionDataAdded(
        address smartAccount,
        uint256 jobId,
        uint48 _executeInterval,
        uint16 _numberOfExecutions,
        uint48 _startDate,
        bytes memory _executionData
    )
        internal
    {
        (
            uint48 executeInterval,
            uint16 numberOfExecutions,
            uint16 numberOfExecutionsCompleted,
            uint48 startDate,
            bool isEnabled,
            uint48 lastExecutionTime,
            bytes memory executionData
        ) = executor.executionLog(smartAccount, jobId);
        assertEq(executeInterval, _executeInterval, "interval");
        assertEq(numberOfExecutions, _numberOfExecutions, "number of executions");
        assertEq(startDate, _startDate, "start date");
        assertEq(isEnabled, true, "enabled");
        assertEq(lastExecutionTime, 0, "last execution time");
        assertEq(numberOfExecutionsCompleted, 0, "number of executions completed");
        assertEq(executionData, _executionData, "execution data");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstallRevertWhen_ModuleIsIntialized() public {
        // it should revert
        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData = abi.encode(address(0x1), address(0x2), uint256(100));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);

        data = abi.encodePacked(SWAP_ROUTER, data);

        executor.onInstall(data);

        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.AlreadyInitialized.selector, address(this))
        );
        executor.onInstall(data);
    }

    function test_OnInstallWhenModuleIsNotIntialized() public {
        // it should set the jobCount to 1
        // it should store the execution config
        // it should emit an ExecutionAdded event
        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData =
            abi.encode(address(0x1), address(0x2), uint256(100), uint160(100), uint256(0));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);

        data = abi.encodePacked(SWAP_ROUTER, data);
        vm.expectEmit(true, true, true, true, address(executor));
        emit SchedulingBase.ExecutionAdded({ smartAccount: address(this), jobId: 1 });

        executor.onInstall(data);

        uint256 jobCount = executor.accountJobCount(address(this));
        assertEq(jobCount, 1);

        checkExecutionDataAdded(
            address(this), 1, _executeInterval, _numberOfExecutions, _startDate, _executionData
        );
    }

    function test_OnUninstallShouldRemoveAllExecutions() public {
        // it should remove all executions
        test_OnInstallWhenModuleIsNotIntialized();

        uint256 jobCount = executor.accountJobCount(address(this));

        executor.onUninstall("");

        for (uint256 i; i < jobCount; i++) {
            (
                uint48 executeInterval,
                uint16 numberOfExecutions,
                uint16 numberOfExecutionsCompleted,
                uint48 startDate,
                bool isEnabled,
                uint48 lastExecutionTime,
                bytes memory executionData
            ) = executor.executionLog(address(this), i);
            assertEq(executeInterval, uint48(0));
            assertEq(numberOfExecutions, uint16(0));
            assertEq(startDate, uint48(0));
            assertEq(isEnabled, false);
            assertEq(lastExecutionTime, 0);
            assertEq(numberOfExecutionsCompleted, 0);
            assertEq(executionData, "");
        }
    }

    function test_OnUninstallShouldSetTheAccountJobCountTo0() public {
        // it should set the account job count to 0
        test_OnInstallWhenModuleIsNotIntialized();

        executor.onUninstall("");

        uint256 jobCount = executor.accountJobCount(address(this));
        assertEq(jobCount, 0);
    }

    function test_OnUninstallShouldEmitAnExecutionsCancelledEvent() public {
        // it should emit an ExecutionsCancelled event
        test_OnInstallWhenModuleIsNotIntialized();

        vm.expectEmit(true, true, true, true, address(executor));
        emit SchedulingBase.ExecutionsCancelled({ smartAccount: address(this) });
        executor.onUninstall("");
    }

    function test_IsInitializedWhenModuleIsNotIntialized() public {
        // it should return false
        bool isInitialized = executor.isInitialized(address(this));
        assertFalse(isInitialized);
    }

    function test_IsInitializedWhenModuleIsIntialized() public {
        // it should return true
        test_OnInstallWhenModuleIsNotIntialized();

        bool isInitialized = executor.isInitialized(address(this));
        assertTrue(isInitialized);
    }

    function test_AddOrderRevertWhen_ModuleIsNotIntialized() public {
        // it should revert
        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData =
            abi.encode(address(0x1), address(0x2), uint256(100), uint160(100), uint256(0));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);

        data = abi.encodePacked(SWAP_ROUTER, data);
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        executor.addOrder(data);
    }

    function test_AddOrderWhenModuleIsIntialized() public {
        // it should increment the jobCount by 1
        // it should store the execution config
        // it should emit an ExecutionAdded event
        test_OnInstallWhenModuleIsNotIntialized();

        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData =
            abi.encode(address(0x1), address(0x2), uint256(100), uint160(100), uint256(0));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);
        data = abi.encodePacked(SWAP_ROUTER, data);

        uint256 prevJobCount = executor.accountJobCount(address(this));

        vm.expectEmit(true, true, true, true, address(executor));
        emit SchedulingBase.ExecutionAdded({ smartAccount: address(this), jobId: prevJobCount + 1 });

        executor.addOrder(data);

        uint256 jobCount = executor.accountJobCount(address(this));
        assertEq(jobCount, prevJobCount + 1);

        checkExecutionDataAdded(
            address(this), 1, _executeInterval, _numberOfExecutions, _startDate, _executionData
        );
    }

    function test_ToggleOrderRevertWhen_OrderDoesNotExist() public {
        // it should revert
        test_OnInstallWhenModuleIsNotIntialized();

        vm.expectRevert(abi.encodeWithSelector(SchedulingBase.InvalidExecution.selector));
        executor.toggleOrder(2);
    }

    function test_ToggleOrderWhenOrderExists() public {
        // it should toggle the order enabled state
        // it should emit an ExecutionStatusUpdated event
        test_OnInstallWhenModuleIsNotIntialized();

        uint256 jobId = 1;

        vm.expectEmit(true, true, true, true, address(executor));
        emit SchedulingBase.ExecutionStatusUpdated({ smartAccount: address(this), jobId: jobId });

        executor.toggleOrder(jobId);

        (,,,, bool isEnabled,,) = executor.executionLog(address(this), jobId);
        assertFalse(isEnabled);
    }

    function test_ExecuteOrderRevertWhen_OrderIsNotEnabled() public {
        // it should revert
        test_OnInstallWhenModuleIsNotIntialized();
        uint256 jobId = 1;
        executor.toggleOrder(jobId);

        vm.startPrank(address(target));
        vm.expectRevert(abi.encodeWithSelector(SchedulingBase.InvalidExecution.selector));
        executor.executeOrder(jobId, 0, 0, FEE);
        vm.stopPrank();
    }

    function test_ExecuteOrderRevertWhen_TheOrderIsNotDue() public whenOrderIsEnabled {
        // it should revert
        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData = abi.encode(address(usdc), address(weth), uint256(100));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);

        data = abi.encodePacked(SWAP_ROUTER, data);
        vm.prank(address(target));
        executor.onInstall(data);

        uint256 jobId = 1;

        checkExecutionDataAdded(
            address(target),
            jobId,
            _executeInterval,
            _numberOfExecutions,
            _startDate,
            _executionData
        );

        vm.startPrank(address(target));
        executor.executeOrder(jobId, _getSqrt(), 0, FEE);

        uint160 sqrt = _getSqrt();

        vm.expectRevert(abi.encodeWithSelector(SchedulingBase.InvalidExecution.selector));
        executor.executeOrder(jobId, sqrt, 0, FEE);
        vm.stopPrank();
    }

    function test_ExecuteOrderRevertWhen_AllExecutionsHaveBeenCompleted()
        public
        whenOrderIsEnabled
        whenTheOrderIsDue
    {
        // it should revert
        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 1;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData = abi.encode(address(0x1), address(0x2), uint256(100));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);
        data = abi.encodePacked(SWAP_ROUTER, data);

        vm.prank(address(target));
        executor.onInstall(data);

        uint256 jobId = 1;

        checkExecutionDataAdded(
            address(target),
            jobId,
            _executeInterval,
            _numberOfExecutions,
            _startDate,
            _executionData
        );

        vm.startPrank(address(target));
        executor.executeOrder(jobId, _getSqrt(), 0, FEE);

        uint160 sqrt = _getSqrt();
        vm.expectRevert(abi.encodeWithSelector(SchedulingBase.InvalidExecution.selector));
        executor.executeOrder(jobId, sqrt, 0, FEE);
        vm.stopPrank();
    }

    function test_ExecuteOrderRevertWhen_TheStartDateIsInTheFuture()
        public
        whenOrderIsEnabled
        whenTheOrderIsDue
        whenAllExecutionsHaveNotBeenCompleted
    {
        // it should revert
        uint48 _executeInterval = 1 days;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp + 1 days);
        bytes memory _executionData =
            abi.encode(address(0x1), address(0x2), uint256(100), uint160(100), uint256(0));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);

        data = abi.encodePacked(SWAP_ROUTER, data);
        vm.prank(address(target));
        executor.onInstall(data);

        uint256 jobId = 1;

        checkExecutionDataAdded(
            address(target),
            jobId,
            _executeInterval,
            _numberOfExecutions,
            _startDate,
            _executionData
        );

        vm.startPrank(address(target));
        vm.expectRevert(abi.encodeWithSelector(SchedulingBase.InvalidExecution.selector));
        executor.executeOrder(jobId, 0, 0, FEE);
        vm.stopPrank();
    }

    function test_ExecuteOrderWhenTheStartDateIsInThePast()
        public
        whenOrderIsEnabled
        whenTheOrderIsDue
        whenAllExecutionsHaveNotBeenCompleted
    {
        // it should swap the stored order
        // it should update the last order timestamp
        // it should update the order execution count
        // it should emit an ExecutionTriggered event
        uint48 _executeInterval = 1 seconds;
        uint16 _numberOfExecutions = 10;
        uint48 _startDate = uint48(block.timestamp);
        bytes memory _executionData = abi.encode(address(0x1), address(0x2), uint256(100));
        bytes memory data =
            abi.encodePacked(_executeInterval, _numberOfExecutions, _startDate, _executionData);

        data = abi.encodePacked(SWAP_ROUTER, data);
        vm.prank(address(target));
        executor.onInstall(data);

        uint256 jobId = 1;

        checkExecutionDataAdded(
            address(target),
            jobId,
            _executeInterval,
            _numberOfExecutions,
            _startDate,
            _executionData
        );

        vm.startPrank(address(target));
        vm.warp(block.timestamp + 1 days);
        executor.executeOrder(jobId, _getSqrt(), 0, FEE);
        vm.stopPrank();

        uint256 value = target.value();
        assertGt(value, 0);
    }

    function test_NameShouldReturnScheduledOrders() public {
        // it should return ScheduledOrders
        string memory name = executor.name();
        assertEq(name, "ScheduledOrders");
    }

    function test_VersionShouldReturn100() public {
        // it should return 1.0.0
        string memory version = executor.version();
        assertEq(version, "1.0.0");
    }

    function test_IsModuleTypeWhenTypeIDIs2() public {
        // it should return true
        bool isModuleType = executor.isModuleType(2);
        assertTrue(isModuleType);
    }

    function test_IsModuleTypeWhenTypeIDIsNot2() public {
        // it should return false
        bool isModuleType = executor.isModuleType(1);
        assertFalse(isModuleType);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    MODIFIERS
    //////////////////////////////////////////////////////////////////////////*/

    modifier whenOrderIsEnabled() {
        _;
    }

    modifier whenTheOrderIsDue() {
        _;
    }

    modifier whenAllExecutionsHaveNotBeenCompleted() {
        _;
    }

    function _getSqrt() internal returns (uint160) {
        uint32 slippage = 1; // 0.1% slippage
        address poolAddress =
            executor.getPoolAddress(FACTORY_ADDRESS, address(usdc), address(weth), FEE);
        uint160 sqrtPriceX96 = executor.getSqrtPriceX96(poolAddress);
        uint256 priceRatio = uniswapHelper.sqrtPriceX96toPriceRatio(sqrtPriceX96);
        uint256 price = uniswapHelper.priceRatioToPrice(priceRatio, poolAddress, address(usdc));
        bool swapToken0to1 = executor.checkTokenOrder(address(usdc), poolAddress);
        uint256 priceRatioLimit;
        if (swapToken0to1) {
            priceRatioLimit = (priceRatio * (1000 - slippage)) / 1000;
        } else {
            priceRatioLimit = (priceRatio * (1000 + slippage)) / 1000;
        }
        uint256 priceLimit = uniswapHelper.priceRatioToPrice(priceRatioLimit, poolAddress, address(usdc));
        uint160 sqrtPriceLimitX96 = uniswapHelper.priceRatioToSqrtPriceX96(priceRatioLimit);

        return sqrtPriceLimitX96;
    }
}
