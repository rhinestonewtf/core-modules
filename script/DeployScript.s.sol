// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import { AutoSavings } from "src/AutoSavings/AutoSavings.sol";
import { ColdStorageHook } from "src/ColdStorageHook/ColdStorageHook.sol";
import { ColdStorageFlashloan } from "src/ColdStorageHook/ColdStorageFlashloan.sol";
import { DeadmanSwitch } from "src/DeadmanSwitch/DeadmanSwitch.sol";
import { HookMultiPlexer } from "src/HookMultiPlexer/HookMultiPlexer.sol";
import { MultiFactor } from "src/MultiFactor/MultiFactor.sol";
import { OwnableExecutor } from "src/OwnableExecutor/OwnableExecutor.sol";
import { OwnableValidator } from "src/OwnableValidator/OwnableValidator.sol";
import { RegistryHook } from "src/RegistryHook/RegistryHook.sol";
import { ScheduledOrders } from "src/ScheduledOrders/ScheduledOrders.sol";
import { ScheduledTransfers } from "src/ScheduledTransfers/ScheduledTransfers.sol";
import { SocialRecovery } from "src/SocialRecovery/SocialRecovery.sol";
import { FlashloanCallback } from "src/Flashloan/FlashloanCallback.sol";
import { FlashloanLender } from "src/Flashloan/flashloanLender.sol";

import "forge-std/console2.sol";

interface IRegistry {
    function deployModule(
        bytes32 salt,
        bytes32 resolverUID,
        bytes calldata initCode,
        bytes calldata metadata,
        bytes calldata resolverContext
    )
        external
        payable
        returns (address moduleAddress);
}

struct Deployments {
    address ownableValidator;
    address ownableExecutor;
    address autosavings;
    address flashloanCallback;
    address flashloanLender;
    address coldStorageHook;
    address coldStorageFlashloan;
    address deadmanSwitch;
    address hookMultiPlexer;
    address multiFactor;
    address registryHook;
    address scheduledOrders;
    address scheduledTransfers;
    address socialRecovery;
    address deployer;
    bytes32 salt;
}

/**
 * @title Deploy
 * @author @kopy-kat
 */
contract DeployScript is Script {
    address registry = 0x0000000000E23E0033C3e93D9D4eBc2FF2AB2AEF;
    IRegistry _registry = IRegistry(registry);

    function run() public {
        bytes32 salt = bytes32(0x0000000000000000000000000000000000000000000000000000000000001338);
        bytes32 resolverUID =
            bytes32(0xDBCA873B13C783C0C9C6DDFC4280E505580BF6CC3DAC83F8A0F7B44ACAAFCA4F);
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        Deployments memory env;

        env.deployer = vm.addr(vm.envUint("PRIVATE_KEY"));
        env.salt = salt;

        env.ownableValidator =
            _registry.deployModule(salt, resolverUID, type(OwnableValidator).creationCode, "", "");
        env.ownableExecutor =
            _registry.deployModule(salt, resolverUID, type(OwnableExecutor).creationCode, "", "");
        env.coldStorageHook =
            _registry.deployModule(salt, resolverUID, type(ColdStorageHook).creationCode, "", "");
        env.coldStorageFlashloan = _registry.deployModule(
            salt, resolverUID, type(ColdStorageFlashloan).creationCode, "", ""
        );

        env.autosavings =
            _registry.deployModule(salt, resolverUID, type(AutoSavings).creationCode, "", "");

        env.deadmanSwitch =
            _registry.deployModule(salt, resolverUID, type(DeadmanSwitch).creationCode, "", "");
        env.hookMultiPlexer = _registry.deployModule(
            salt,
            resolverUID,
            abi.encodePacked(type(HookMultiPlexer).creationCode, abi.encode(registry)),
            "",
            ""
        );
        env.multiFactor = _registry.deployModule(
            salt,
            resolverUID,
            abi.encodePacked(type(MultiFactor).creationCode, abi.encode(registry)),
            "",
            ""
        );
        env.registryHook =
            _registry.deployModule(salt, resolverUID, type(RegistryHook).creationCode, "", "");
        env.scheduledOrders =
            _registry.deployModule(salt, resolverUID, type(ScheduledOrders).creationCode, "", "");
        env.scheduledTransfers =
            _registry.deployModule(salt, resolverUID, type(ScheduledTransfers).creationCode, "", "");
        env.socialRecovery =
            _registry.deployModule(salt, resolverUID, type(SocialRecovery).creationCode, "", "");

        vm.stopBroadcast();

        _logJson(env);
    }

    function _logJson(Deployments memory env) internal {
        string memory root = "some key";
        vm.serializeUint(root, "chainId", block.chainid);
        vm.serializeAddress(root, "broadcastEOA", env.deployer);

        string memory deployments = "deployments";

        string memory item = "OwnableValidator";
        vm.serializeAddress(item, "address", env.ownableValidator);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "ownableValidator", item);

        item = "OwnableExecutor";
        vm.serializeAddress(item, "address", env.ownableExecutor);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "ownableExecutor", item);

        item = "ColdStorageHook";
        vm.serializeAddress(item, "address", env.coldStorageHook);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);

        vm.serializeString(deployments, "coldStorageHook", item);

        item = "ColdStorageFlashloan";
        vm.serializeAddress(item, "address", env.coldStorageFlashloan);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "coldStorageFlashloan", item);

        item = "DeadmanSwitch";
        vm.serializeAddress(item, "address", env.deadmanSwitch);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "deadmanSwitch", item);

        item = "HookMultiPlexer";
        vm.serializeAddress(item, "address", env.hookMultiPlexer);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "hookMultiPlexer", item);

        item = "MultiFactor";
        vm.serializeAddress(item, "address", env.multiFactor);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "multiFactor", item);

        item = "RegistryHook";
        vm.serializeAddress(item, "address", env.registryHook);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "registryHook", item);

        item = "AutoSavings";
        vm.serializeAddress(item, "address", env.autosavings);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "autoSavings", item);

        item = "ScheduledOrders";
        vm.serializeAddress(item, "address", env.scheduledOrders);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "scheduledOrders", item);

        item = "ScheduledTransfers";
        vm.serializeAddress(item, "address", env.scheduledTransfers);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "scheduledTransfers", item);

        item = "SocialRecovery";
        vm.serializeAddress(item, "address", env.socialRecovery);
        vm.serializeBytes32(item, "salt", env.salt);
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", registry);
        vm.serializeString(deployments, "socialRecovery", item);

        string memory output = vm.serializeUint(deployments, "timestamp", block.timestamp);
        string memory finalJson = vm.serializeString(root, "deployments", output);

        string memory fileName =
            string(abi.encodePacked("./deployments/", Strings.toString(block.chainid), ".json"));
        console2.log("Writing to file: ", fileName);

        vm.writeJson(finalJson, fileName);
    }
}
