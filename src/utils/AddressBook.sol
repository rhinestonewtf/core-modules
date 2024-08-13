address constant MAINNET_SWAPROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
address constant POLYGON_SWAPROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;

uint256 constant MAINNET = 1;
uint256 constant POLYGON = 137;
uint256 constant BSC = 56;
uint256 constant FANTOM = 250;
uint256 constant XDAI = 100;
uint256 constant ARBITRUM = 42_161;
uint256 constant AVALANCHE = 43_114;
uint256 constant CELO = 42_220;

contract AddressBook {
    address public immutable swaprouter;

    constructor() {
        uint256 chainId = block.chainid;

        if (chainId == MAINNET) {
            swaprouter = MAINNET_SWAPROUTER;
        } else if (chainId == POLYGON) {
            swaprouter = POLYGON_SWAPROUTER;
        } else {
            revert("AddressBook: Invalid ChainId");
        }
    }
}
