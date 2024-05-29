// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { EnumerableMap } from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

// Hook types
enum HookType {
    GLOBAL,
    DELEGATECALL,
    VALUE,
    SIG,
    TARGET_SIG
}

// Hook initialization data for sig hooks
struct SigHookInit {
    bytes4 sig;
    address[] subHooks;
}

struct HookAndContext {
    address hook;
    bytes context;
}

// Config for an account
// We also need to store an array of sigs and target sigs to be able to remove them on uninstall
struct ConfigOLD {
    address[] globalHooks;
    address[] delegatecallHooks;
    address[] valueHooks;
    bytes4[] sigs;
    mapping(bytes4 => address[]) sigHooks;
    bytes4[] targetSigs;
    mapping(bytes4 => address[]) targetSigHooks;
}

struct SignatureHooks {
    bytes4[] allSigs;
    mapping(bytes4 => address[]) sigHooks;
}

struct Config {
    mapping(HookType hookType => address[]) hooks;
    mapping(HookType hookType => SignatureHooks) sigHooks;
}
