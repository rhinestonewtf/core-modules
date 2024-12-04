import { FlashLoanType, IERC3156FlashBorrower, IERC3156FlashLender } from "modulekit/Interfaces.sol";
import { Execution } from "modulekit/external/ERC7579.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

bytes32 constant FLASHLOAN_EXEC_TYPEHASH = keccak256(
    "SignedFlashloanExecution(address borrower,address lender,uint8 flashLoanType,address token,uint256 amount,Execution[] executions,uint256 nonce)"
);

bytes32 constant EXECUTION_TYPEHASH =
    0x37fb04e5593580b36bfacc47d8b1a4b9a2acb88a513bf153760f925a6723d4b5;

library HashLib {
    using EfficientHashLib for bytes32[];

    function hashExecutionArrayMemory(Execution[] memory executionArray)
        internal
        pure
        returns (bytes32)
    {
        uint256 length = executionArray.length;

        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, hashExecutionMemory(executionArray[i]));
        }
        return a.hash();
    }

    function hashExecutionMemory(Execution memory execution) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EXECUTION_TYPEHASH, execution.target, execution.value, keccak256(execution.callData)
            )
        );
    }

    function hashFlashloanExec(
        address borrower,
        address lender,
        FlashLoanType flashLoanType,
        address token,
        uint256 amount,
        Execution[] memory executions,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                FLASHLOAN_EXEC_TYPEHASH,
                borrower,
                lender,
                flashLoanType,
                token,
                amount,
                hashExecutionArrayMemory(executions),
                nonce
            )
        );
    }
}
