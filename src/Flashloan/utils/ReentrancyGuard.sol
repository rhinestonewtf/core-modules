// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

/**
 * @title ReentrancyGuard
 * @dev Helps contracts guard against reentrancy attacks
 * reentrancy is checked for each account individually, since its possible that a different account
 * is chaining flashloan uses
 * @author zeroknots
 */
contract ReentrancyGuard {
    error ReentrancyGuardReentrantCall();

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    function _computeSlot() internal view returns (bytes32 slot) {
        slot = keccak256(abi.encodePacked(msg.sender));
    }

    function set(uint256 value) internal {
        bytes32 hashSlot = _computeSlot();

        assembly {
            tstore(hashSlot, value)
        }
    }

    function get() internal view returns (uint256 value) {
        bytes32 hashSlot = _computeSlot();

        assembly {
            value := tload(hashSlot)
        }
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (get() == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        set(ENTERED);
    }

    function _nonReentrantAfter() private {
        set(NOT_ENTERED);
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }
}
