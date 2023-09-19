// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

// File contracts/roles/ChronicleVerseTreasuryNode.sol
/**
 * @notice A mixin that stores a reference to the ChronicleVerse treasury contract.
 */
abstract contract ChronicleVerseTreasuryNode {
    using Address for address payable;

    address payable private treasury;

    /**
     * @dev Called once after the initial deployment to set the ChronicleVerse treasury address.
     */
    constructor(
        address payable _treasury
    ) {
        require(
            _treasury.isContract(),
            "ChronicleVerseTreasuryNode: Address is not a contract"
        );
        treasury = _treasury;
    }

    /**
     * @notice Returns the address of the ChronicleVerse treasury.
     */
    function getChronicleVerseTreasury() public view returns (address payable) {
        return treasury;
    }

}

// File contracts/interfaces/IAdminRole.sol
/**
 * @notice Interface for AdminRole which wraps the default admin role from
 * OpenZeppelin's AccessControl for easy integration.
 */
interface IAdminRole {
    function isAdmin(address account) external view returns (bool);
}

// File contracts/roles/ChronicleVerseAdminRole.sol
/**
 * @notice Allows a contract to leverage the admin role defined by the ChronicleVerse treasury.
 */
abstract contract ChronicleVerseAdminRole is ChronicleVerseTreasuryNode {
    // This file uses 0 data slots (other than what's included via ChronicleVerseTreasuryNode)

    modifier onlyChronicleVerseAdmin() {
        require(
            _isChronicleVerseAdmin(),
            "ChronicleVerseAdminRole: caller does not have the Admin role"
        );
        _;
    }

    function _isChronicleVerseAdmin() internal view returns (bool) {
        return IAdminRole(getChronicleVerseTreasury()).isAdmin(msg.sender);
    }
}

// File contracts/interfaces/IOperatorRole.sol
/**
 * @notice Interface for OperatorRole which wraps a role from
 * OpenZeppelin's AccessControl for easy integration.
 */
interface IOperatorRole {
    function isOperator(address account) external view returns (bool);
}

// File contracts/roles/ChronicleVerseOperatorRole.sol
/**
 * @notice Allows a contract to leverage the operator role defined by the ChronicleVerse treasury.
 */
abstract contract ChronicleVerseOperatorRole is ChronicleVerseTreasuryNode {
    // This file uses 0 data slots (other than what's included via ChronicleVerseTreasuryNode)

    function _isChronicleVerseOperator() internal view returns (bool) {
        return IOperatorRole(getChronicleVerseTreasury()).isOperator(msg.sender);
    }
}

// File contracts/mixins/NFTMarketCore.sol
/**
 * @notice A place for common modifiers and functions used by various NFTMarket mixins, if any.
 * @dev This also leaves a gap which can be used to add a new mixin to the top of the inheritance tree.
 */
abstract contract NFTMarketCore {
    /**
     * @dev If the auction did not have an escrowed seller to return, this falls back to return the current owner.
     * This allows functions to calculate the correct fees before the NFT has been listed in auction.
     */
    function _getSellerFor(
        address nftContract,
        uint256 tokenId
    ) internal view virtual returns (address payable) {
        return payable(IERC721(nftContract).ownerOf(tokenId));
    }

}

// File contracts/mixins/SendValueWithFallbackWithdraw.sol
/**
 * @notice Attempt to send ETH and if the transfer fails or runs out of gas, store the balance
 * for future withdrawal instead.
 */
abstract contract SendValueWithFallbackWithdraw is ReentrancyGuard {
    using Address for address payable;
    using SafeMath for uint256;

    mapping(address => uint256) private pendingWithdrawals;

    event WithdrawPending(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @notice Returns how much funds are available for manual withdraw due to failed transfers.
     */
    function getPendingWithdrawal(address user) public view returns (uint256) {
        return pendingWithdrawals[user];
    }

    /**
     * @notice Allows a user to manually withdraw funds which originally failed to transfer to themselves.
     */
    function withdraw() public {
        withdrawFor(payable(msg.sender));
    }

    /**
     * @notice Allows anyone to manually trigger a withdrawal of funds which originally failed to transfer for a user.
     */
    function withdrawFor(address payable user) public nonReentrant {
        uint256 amount = pendingWithdrawals[user];
        require(amount > 0, "No funds are pending withdrawal");
        pendingWithdrawals[user] = 0;
        user.sendValue(amount);
        emit Withdrawal(user, amount);
    }

    /**
     * @dev Attempt to send a user ETH with a reasonably low gas limit of 20k,
     * which is enough to send to contracts as well.
     */
    function _sendValueWithFallbackWithdrawWithLowGasLimit(
        address mode,
        address payable user,
        uint256 amount
    ) internal {
        _sendValueWithFallbackWithdraw(mode, user, amount, 20000);
    }

    /**
     * @dev Attempt to send a user or contract ETH with a moderate gas limit of 90k,
     * which is enough for a 5-way split.
     */
    function _sendValueWithFallbackWithdrawWithMediumGasLimit(
        address paymentMode,
        address payable user,
        uint256 amount
    ) internal {
        _sendValueWithFallbackWithdraw(paymentMode, user, amount, 210000);
    }

    /**
     * @dev Attempt to send a user or contract ETH and if it fails store the amount owned for later withdrawal.
     */
    function _sendValueWithFallbackWithdraw(
        address mode,
        address payable user,
        uint256 amount,
        uint256 gasLimit
    ) private {
        if (amount == 0) {
            return;
        }
        if (mode == address(0)) {
            // Cap the gas to prevent consuming all available gas to block a tx from completing successfully
            // solhint-disable-next-line avoid-low-level-calls
            (bool success, ) = user.call{value: amount, gas: gasLimit}("");
            if (!success) {
                // Record failed sends for a withdrawal later
                // Transfers could fail if sent to a multisig with non-trivial receiver logic
                // solhint-disable-next-line reentrancy
                pendingWithdrawals[user] = pendingWithdrawals[user].add(amount);
                emit WithdrawPending(user, amount);
            }
        } else {
            require(IERC20(mode).transfer(user, amount));
        }
    }

}

// File contracts/interfaces/IWHISKYNFT721.sol
// solhint-disable
interface IWHISKYNFT721 {
    function tokenCreator(
        uint256 tokenId
    ) external view returns (address payable);

    function getTokenCreatorPaymentAddress(
        uint256 tokenId
    ) external view returns (address payable);

    function getTokenRoyalty(uint256 tokenId) external view returns (uint256);

    function isExists(uint tokenId) external view returns (bool);
}

// File contracts/mixins/NFTMarketCreators.sol
/**
 * @notice A mixin for associating creators to NFTs.
 * @dev In the future this may store creators directly in order to support NFTs created on a different platform.
 */
abstract contract NFTMarketCreators is
    ReentrancyGuard // Adding this unused mixin to help with linearization
{
    /**
     * @dev If the creator is not available then 0x0 is returned. Downstream this indicates that the creator
     * fee should be sent to the current seller instead.
     * This may apply when selling NFTs that were not minted on ChronicleVerse.
     */
    function _getCreator(
        address nftContract,
        uint256 tokenId
    ) internal view returns (address payable) {
        try IWHISKYNFT721(nftContract).tokenCreator(tokenId) returns (
            address payable creator
        ) {
            return creator;
        } catch {
            return payable(address(0));
        }
    }

    /**
     * @dev Returns the creator and a destination address for any payments to the creator,
     * returns address(0) if the creator is unknown.
     */
    function _getCreatorAndPaymentAddress(
        address nftContract,
        uint256 tokenId
    ) internal view returns (address payable, address payable) {
        address payable creator = _getCreator(nftContract, tokenId);
        try
            IWHISKYNFT721(nftContract).getTokenCreatorPaymentAddress(tokenId)
        returns (address payable tokenCreatorPaymentAddress) {
            if (tokenCreatorPaymentAddress != address(0)) {
                return (creator, tokenCreatorPaymentAddress);
            }
        } catch // solhint-disable-next-line no-empty-blocks
        {
            // Fall through to return (creator, creator) below
        }
        return (creator, creator);
    }

}

// File contracts/mixins/Constants.sol
/**
 * @dev Constant values shared across mixins.
 */
abstract contract Constants {
    uint256 internal constant BASIS_POINTS = 10000;
}

// File contracts/mixins/NFTMarketFees.sol
/**
 * @notice A mixin to distribute funds when an NFT is sold.
 */
abstract contract NFTMarketFees is
    Constants,
    ChronicleVerseTreasuryNode,
    NFTMarketCore,
    NFTMarketCreators,
    SendValueWithFallbackWithdraw
{
    using SafeMath for uint256;

    event MarketFeesUpdated(
        uint256 primaryChronicleVerseFeeBasisPoints,
        uint256 secondaryChronicleVerseFeeBasisPoints
    );

    uint256 private _primaryChronicleVerseFeeBasisPoints;
    uint256 private _secondaryChronicleVerseFeeBasisPoints;

    mapping(address => mapping(uint256 => bool))
        private nftContractToTokenIdToFirstSaleCompleted;

    /**
     * @notice Returns true if the given NFT has not been sold in this market previously and is being sold by the creator.
     */
    function getIsPrimary(
        address nftContract,
        uint256 tokenId
    ) public view returns (bool) {
        return
            _getIsPrimary(
                nftContract,
                tokenId,
                _getCreator(nftContract, tokenId),
                _getSellerFor(nftContract, tokenId)
            );
    }

    /**
     * @dev A helper that determines if this is a primary sale given the current seller.
     * This is a minor optimization to use the seller if already known instead of making a redundant lookup call.
     */
    function _getIsPrimary(
        address nftContract,
        uint256 tokenId,
        address creator,
        address seller
    ) private view returns (bool) {
        return
            !nftContractToTokenIdToFirstSaleCompleted[nftContract][tokenId] &&
            creator == seller;
    }

    /**
     * @notice Returns the current fee configuration in basis points.
     */
    function getFeeConfig(
        address nftContract,
        uint256 tokenId
    )
        public
        view
        returns (
            uint256 primaryChronicleVerseFeeBasisPoints,
            uint256 secondaryChronicleVerseFeeBasisPoints,
            uint256 secondaryCreatorFeeBasisPoints
        )
    {
        return (
            _primaryChronicleVerseFeeBasisPoints,
            _secondaryChronicleVerseFeeBasisPoints,
            IWHISKYNFT721(nftContract).getTokenRoyalty(tokenId)
        );
    }

    /**
     * @notice Returns the fees of foundation in basis points
     */

    function getChronicleVerseFees()
        public
        view
        returns (
            uint256 primaryChronicleVerseFeeBasisPoints,
            uint256 secondaryChronicleVerseFeeBasisPoints
        )
    {
        return (_primaryChronicleVerseFeeBasisPoints, _secondaryChronicleVerseFeeBasisPoints);
    }

    /**
     * @notice Returns how funds will be distributed for a sale at the given price point.
     * @dev This could be used to present exact fee distributing on listing or before a bid is placed.
     */
    function getFees(
        address nftContract,
        uint256 tokenId,
        uint256 price
    )
        public
        view
        returns (
            uint256 foundationFee,
            uint256 creatorSecondaryFee,
            uint256 ownerRev
        )
    {
        (foundationFee, , creatorSecondaryFee, , ownerRev) = _getFees(
            nftContract,
            tokenId,
            _getSellerFor(nftContract, tokenId),
            price
        );
    }

    /**
     * @dev Calculates how funds should be distributed for the given sale details.
     * If this is a primary sale, the creator revenue will appear as `ownerRev`.
     */
    function _getFees(
        address nftContract,
        uint256 tokenId,
        address payable seller,
        uint256 price
    )
        private
        view
        returns (
            uint256 foundationFee,
            address payable creatorSecondaryFeeTo,
            uint256 creatorSecondaryFee,
            address payable ownerRevTo,
            uint256 ownerRev
        )
    {
        // The tokenCreatorPaymentAddress replaces the creator as the fee recipient.
        (
            address payable creator,
            address payable tokenCreatorPaymentAddress
        ) = _getCreatorAndPaymentAddress(nftContract, tokenId);
        uint256 foundationFeeBasisPoints;
        if (_getIsPrimary(nftContract, tokenId, creator, seller)) {
            foundationFeeBasisPoints = _primaryChronicleVerseFeeBasisPoints;
            // On a primary sale, the creator is paid the remainder via `ownerRev`.
            ownerRevTo = tokenCreatorPaymentAddress;
        } else {
            uint256 secondaryCreatorFeeBasisPoints = IWHISKYNFT721(nftContract)
                .getTokenRoyalty(tokenId);
            foundationFeeBasisPoints = _secondaryChronicleVerseFeeBasisPoints;

            // If there is no creator then funds go to the seller instead.
            if (tokenCreatorPaymentAddress != address(0)) {
                // SafeMath is not required when dividing by a constant value > 0.
                creatorSecondaryFee =
                    price.mul(secondaryCreatorFeeBasisPoints) /
                    BASIS_POINTS;
                creatorSecondaryFeeTo = tokenCreatorPaymentAddress;
            }

            if (seller == creator) {
                ownerRevTo = tokenCreatorPaymentAddress;
            } else {
                ownerRevTo = seller;
            }
        }
        // SafeMath is not required when dividing by a constant value > 0.
        foundationFee = price.mul(foundationFeeBasisPoints) / BASIS_POINTS;
        ownerRev = price.sub(foundationFee).sub(creatorSecondaryFee);
    }

    /**
     * @dev Distributes funds to foundation, creator, and NFT owner after a sale.
     */
    function _distributeFunds(
        address mode,
        address nftContract,
        uint256 tokenId,
        address payable seller,
        uint256 price
    )
        internal
        returns (uint256 foundationFee, uint256 creatorFee, uint256 ownerRev)
    {
        address payable creatorFeeTo;
        address payable ownerRevTo;
        (
            foundationFee,
            creatorFeeTo,
            creatorFee,
            ownerRevTo,
            ownerRev
        ) = _getFees(nftContract, tokenId, seller, price);

        // Anytime fees are distributed that indicates the first sale is complete,
        // which will not change state during a secondary sale.
        // This must come after the `_getFees` call above as this state is considered in the function.
        nftContractToTokenIdToFirstSaleCompleted[nftContract][tokenId] = true;

        _sendValueWithFallbackWithdrawWithLowGasLimit(
            mode,
            getChronicleVerseTreasury(),
            foundationFee
        );
        _sendValueWithFallbackWithdrawWithMediumGasLimit(
            mode,
            creatorFeeTo,
            creatorFee
        );
        _sendValueWithFallbackWithdrawWithMediumGasLimit(
            mode,
            ownerRevTo,
            ownerRev
        );
    }

    /**
     * @notice Allows ChronicleVerse to change the market fees.
     */
    function _updateMarketFees(
        uint256 primaryChronicleVerseFeeBasisPoints,
        uint256 secondaryChronicleVerseFeeBasisPoints
    ) internal {
        require(
            primaryChronicleVerseFeeBasisPoints < BASIS_POINTS,
            "NFTMarketFees: Fees >= 100%"
        );

        require(
            secondaryChronicleVerseFeeBasisPoints < BASIS_POINTS,
            "NFTMarketFees: Fees >= 100%"
        );

        _primaryChronicleVerseFeeBasisPoints = primaryChronicleVerseFeeBasisPoints;
        _secondaryChronicleVerseFeeBasisPoints = secondaryChronicleVerseFeeBasisPoints;

        emit MarketFeesUpdated(
            primaryChronicleVerseFeeBasisPoints,
            secondaryChronicleVerseFeeBasisPoints
        );
    }

}

/**
 * @notice Adds support for a private sale of an NFT directly between two parties.
 */
abstract contract NFTMarketPrivateSale is NFTMarketFees {
    /**
     * @dev This name is used in the EIP-712 domain.
     * If multiple classes use EIP-712 signatures in the future this can move to the shared constants file.
     */
    string private constant NAME = "ChronicleVerseMarket";
    /**
     * @dev This is a hash of the method signature used in the EIP-712 signature for private sales.
     */
    bytes32 private constant BUY_FROM_PRIVATE_SALE_TYPEHASH =
        keccak256(
            "BuyFromPrivateSale(address nftContract,uint256 tokenId,address buyer,uint256 price,uint256 deadline)"
        );

    /**
     * @dev This is the domain used in EIP-712 signatures.
     * It is not a constant so that the chainId can be determined dynamically.
     * If multiple classes use EIP-712 signatures in the future this can move to a shared file.
     */
    bytes32 private DOMAIN_SEPARATOR;

    event PrivateSaleFinalized(
        address paymentMode,
        address indexed nftContract,
        uint256 indexed tokenId,
        address indexed seller,
        address buyer,
        uint256 creatorFee,
        uint256 ownerRev,
        uint256 deadline
    );

    /**
     * @dev This function must be called at least once before signatures will work as expected.
     * It's okay to call this function many times. Subsequent calls will have no impact.
     */
    function _reinitialize() internal {
        uint256 chainId;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(NAME)),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    /**
     * @notice Allow two parties to execute a private sale.
     * @dev The seller signs a message approving the sale, and then the buyer calls this function
     * with the msg.value equal to the agreed upon price.
     * The sale is executed in this single on-chain call including the transfer of funds and the NFT.
     */
    function buyFromPrivateSale(
        IERC721 nftContract,
        address paymentMode,
        uint256 amount,
        uint256 tokenId,
        uint256 deadline,
        bytes memory signature
    ) public payable {
        // The signed message from the seller is only valid for a limited time.
        require(deadline >= block.timestamp, "NFTMarketPrivateSale:EXPIRED");
        // The seller must have the NFT in their wallet when this function is called.
        address payable seller = payable(nftContract.ownerOf(tokenId));

        // if (paymentMode == address(0)) amount = msg.value;

        // Scoping this block to avoid a stack too deep error
        {
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    // DOMAIN_SEPARATOR, //Need to be added in future
                    keccak256(
                        abi.encode(
                            BUY_FROM_PRIVATE_SALE_TYPEHASH,
                            nftContract,
                            tokenId,
                            // msg.sender,
                            amount,
                            deadline
                        )
                    )
                )
            );

            digest = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
            );

            // Revert if the signature is invalid, the terms are not as expected, or if the seller transferred the NFT.
            require(
                recoverSigner(digest, signature) == seller,
                "NFTMarketPrivateSale:INVALID_SIGNATURE"
            );
        }

        // This will revert if the seller has not given the market contract approval.
        nftContract.transferFrom(seller, msg.sender, tokenId);
        // Pay the seller, creator, and ChronicleVerse as appropriate.
        (, uint256 creatorFee, uint256 ownerRev) = _distributeFunds(
            paymentMode,
            address(nftContract),
            tokenId,
            seller,
            amount
        );

        emit PrivateSaleFinalized(
            paymentMode,
            address(nftContract),
            tokenId,
            seller,
            msg.sender,
            creatorFee,
            ownerRev,
            deadline
        );
    }

    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) public pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            revert("ECDSA: invalid signature 's' value");
        }

        if (v != 27 && v != 28) {
            revert("ECDSA: invalid signature 'v' value");
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            ),
            v,
            r,
            s
        );
        require(signer != address(0), "ECDSA: invalid signature");

        return signer;
    }

}

// File contracts/mixins/NFTMarketAuction.sol
/**
 * @notice An abstraction layer for auctions.
 * @dev This contract can be expanded with reusable calls and data as more auction types are added.
 */
abstract contract NFTMarketAuction {
    /**
     * @dev A global id for auctions of any type.
     */
    uint256 private nextAuctionId;

    constructor() {
        nextAuctionId = 1;
    }

    function _getNextAndIncrementAuctionId() internal returns (uint256) {
        return nextAuctionId++;
    }

}

// File contracts/mixins/AccountMigration.sol
/**
 * @notice Checks for a valid signature authorizing the migration of an account to a new address.
 * @dev This is shared by both the FNDNFT721 and FNDNFTMarket, and the same signature authorizes both.
 */
abstract contract AccountMigration is ChronicleVerseOperatorRole {
    using Address for address;

    // From https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.1.0/contracts/utils/cryptography
    function _isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) private view returns (bool) {
        if (signer.isContract()) {
            try IERC1271(signer).isValidSignature(hash, signature) returns (
                bytes4 magicValue
            ) {
                return magicValue == IERC1271(signer).isValidSignature.selector;
            } catch {
                return false;
            }
        } else {
            return ECDSA.recover(hash, signature) == signer;
        }
    }

    // From https://ethereum.stackexchange.com/questions/8346/convert-address-to-string
    function _toAsciiString(address x) private pure returns (string memory) {
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(
                uint8(uint256(uint160(x)) / (2 ** (8 * (19 - i))))
            );
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 * i + 2] = _char(hi);
            s[2 * i + 3] = _char(lo);
        }
        return string(s);
    }

    function _char(bytes1 b) private pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    // From https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.1.0/contracts/utils/cryptography/ECDSA.sol
    // Modified to accept messages (instead of the message hash)
    function _toEthSignedMessage(
        bytes memory message
    ) private pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n",
                    Strings.toString(message.length),
                    message
                )
            );
    }

    /**
     * @dev Confirms the msg.sender is a ChronicleVerse operator and that the signature provided is valid.
     * @param signature Message `I authorize ChronicleVerse to migrate my account to ${newAccount.address.toLowerCase()}`
     * signed by the original account.
     */
    modifier onlyAuthorizedAccountMigration(
        address originalAddress,
        address newAddress,
        bytes memory signature
    ) {
        require(
            _isChronicleVerseOperator(),
            "AccountMigration: Caller is not an operator"
        );
        bytes32 hash = _toEthSignedMessage(
            abi.encodePacked(
                "I authorize ChronicleVerse to migrate my account to ",
                _toAsciiString(newAddress)
            )
        );
        require(
            _isValidSignatureNow(originalAddress, hash, signature),
            "AccountMigration: Signature must be from the original account"
        );
        _;
    }
}

// File contracts/mixins/NFTMarketReserveAuction.sol
/**
 * @notice Manages a reserve price auction for NFTs.
 */
abstract contract NFTMarketReserveAuction is
    Constants,
    ChronicleVerseAdminRole,
    AccountMigration,
    NFTMarketCore,
    ReentrancyGuard,
    SendValueWithFallbackWithdraw,
    NFTMarketFees,
    NFTMarketAuction
{
    using SafeMath for uint256;

    struct ReserveAuction {
        address nftContract;
        uint256 tokenId;
        address payable seller;
        uint256 startTime;
        uint256 endTime;
        address payable bidder;
        uint256 amount;
        address paymentMode;
    }

    mapping(address => mapping(uint256 => uint256))
        private nftContractToTokenIdToAuctionId;
    mapping(uint256 => ReserveAuction) private auctionIdToAuction;

    mapping(address => bool) public tokens;

    mapping(address => mapping(address => uint256[])) public userTokensOnSale;

    uint256 private _minPercentIncrementInBasisPoints;

    // This variable was used in an older version of the contract, left here as a gap to ensure upgrade compatibility
    uint256 private ______gap_was_maxBidIncrementRequirement;

    // These variables were used in an older version of the contract, left here as gaps to ensure upgrade compatibility
    uint256 private ______gap_was_goLiveDate;

    uint256 private EXTENSION_DURATION;

    event ReserveAuctionConfigUpdated(
        uint256 minPercentIncrementInBasisPoints,
        uint256 maxBidIncrementRequirement,
        uint256 duration,
        uint256 extensionDuration,
        uint256 goLiveDate
    );

    event ReserveAuctionCreated(
        address indexed seller,
        address indexed nftContract,
        uint256 indexed tokenId,
        uint256 reservePrice,
        uint256 auctionId,
        address paymentMode
    );
    event ReserveAuctionUpdated(
        uint256 indexed auctionId,
        uint256 reservePrice
    );
    event ReserveAuctionCanceled(uint256 indexed auctionId);

    event ReserveAuctionBidPlaced(
        uint256 indexed auctionId,
        address indexed bidder,
        uint256 amount,
        uint256 endTime
    );
    event ReserveAuctionFinalized(
        uint256 indexed auctionId,
        address indexed seller,
        address indexed bidder,
        uint256 f8nFee,
        uint256 creatorFee,
        uint256 ownerRev
    );
    event ReserveAuctionCanceledByAdmin(
        uint256 indexed auctionId,
        string reason
    );
    event ReserveAuctionSellerMigrated(
        uint256 indexed auctionId,
        address indexed originalSellerAddress,
        address indexed newSellerAddress
    );
    event TokenUpdated(address indexed tokenAddress, bool indexed status);

    modifier onlyValidAuctionConfig(uint256 reservePrice) {
        require(
            reservePrice > 0,
            "NFTMarketReserveAuction: Reserve price must be at least 1 wei"
        );
        _;
    }

    /**
     * @notice Returns auction details for a given auctionId.
     */
    function getReserveAuction(
        uint256 auctionId
    ) public view returns (ReserveAuction memory) {
        return auctionIdToAuction[auctionId];
    }

    /**
     * @notice Returns the auctionId for a given NFT, or 0 if no auction is found.
     * @dev If an auction is canceled, it will not be returned. However the auction may be over and pending finalization.
     */
    function getReserveAuctionIdFor(
        address nftContract,
        uint256 tokenId
    ) public view returns (uint256) {
        return nftContractToTokenIdToAuctionId[nftContract][tokenId];
    }

    /**
     * @dev Returns the seller that put a given NFT into escrow,
     * or bubbles the call up to check the current owner if the NFT is not currently in escrow.
     */
    function _getSellerFor(
        address nftContract,
        uint256 tokenId
    ) internal view virtual override returns (address payable) {
        address payable seller = auctionIdToAuction[
            nftContractToTokenIdToAuctionId[nftContract][tokenId]
        ].seller;
        if (seller == address(0)) {
            return super._getSellerFor(nftContract, tokenId);
        }
        return seller;
    }

    /**
     * @notice Returns the current configuration for reserve auctions.
     */
    function getReserveAuctionConfig()
        public
        view
        returns (uint256 minPercentIncrementInBasisPoints, uint256 duration)
    {
        minPercentIncrementInBasisPoints = _minPercentIncrementInBasisPoints;
        duration = EXTENSION_DURATION;
    }

    function _updateReserveAuctionConfig(
        uint256 minPercentIncrementInBasisPoints,
        uint256 duration
    ) internal {
        require(
            minPercentIncrementInBasisPoints <= BASIS_POINTS,
            "NFTMarketReserveAuction: Min increment must be <= 100%"
        );

        _minPercentIncrementInBasisPoints = minPercentIncrementInBasisPoints;
        EXTENSION_DURATION = duration;

        // We continue to emit unused configuration variables to simplify the subgraph integration.
        emit ReserveAuctionConfigUpdated(
            minPercentIncrementInBasisPoints,
            0,
            duration,
            EXTENSION_DURATION,
            0
        );
    }

    /**
     * @notice Creates an auction for the given NFT.
     * The NFT is held in escrow until the auction is finalized or canceled.
     */
    function createReserveAuction(
        address nftContract,
        uint256 tokenId,
        uint256 reservePrice,
        uint256 startDate,
        uint256 endDate,
        address paymentMode
    ) public onlyValidAuctionConfig(reservePrice) nonReentrant {
        require(
            tokens[paymentMode],
            "NFTMarketReserveAuction:TOKEN_NOT_SUPPORTED"
        );
        // If an auction is already in progress then the NFT would be in escrow and the modifier would have failed
        uint256 extraTimeForExecution = 10 minutes;
        // require(
        //     startDate + extraTimeForExecution > block.timestamp &&
        //         endDate > startDate + EXTENSION_DURATION,
        //     "NFTMarketReserveAuction:INVALID_ENDDATE"
        // );
        uint256 auctionId = _getNextAndIncrementAuctionId();
        nftContractToTokenIdToAuctionId[nftContract][tokenId] = auctionId;
        userTokensOnSale[msg.sender][nftContract].push(tokenId);
        auctionIdToAuction[auctionId] = ReserveAuction(
            nftContract,
            tokenId,
            payable(msg.sender),
            startDate,
            endDate, // endTime is only known once the reserve price is met
            payable(address(0)), // bidder is only known once a bid has been placed
            reservePrice,
            paymentMode
        );

        IERC721(nftContract).transferFrom(
            msg.sender,
            address(this),
            tokenId
        );

        emit ReserveAuctionCreated(
            msg.sender,
            nftContract,
            tokenId,
            reservePrice,
            auctionId,
            paymentMode
        );
    }

    /**
     * @notice If an auction has been created but has not yet received bids, the configuration
     * such as the reservePrice may be changed by the seller.
     */
    function updateReserveAuction(
        uint256 auctionId,
        uint256 reservePrice
    ) public onlyValidAuctionConfig(reservePrice) {
        ReserveAuction storage auction = auctionIdToAuction[auctionId];
        require(
            auction.seller == msg.sender,
            "NFTMarketReserveAuction:NOT_YOUR_AUCTION"
        );
        require(
            auction.startTime > block.timestamp,
            "NFTMarketReserveAuction:AUCTION_IN_PROGRESS"
        );

        auction.amount = reservePrice;

        emit ReserveAuctionUpdated(auctionId, reservePrice);
    }

    /**
     * @notice If an auction has been created but has not yet received bids, it may be canceled by the seller.
     * The NFT is returned to the seller from escrow.
     */
    function cancelReserveAuction(uint256 auctionId) public nonReentrant {
        ReserveAuction memory auction = auctionIdToAuction[auctionId];
        require(
            auction.seller == msg.sender,
            "NFTMarketReserveAuction:CANCEL_NOT_ALLOWED_DIFFERENT_OWNER"
        );
        require(
            auction.bidder == address(0),
            "NFTMarketReserveAuction:AUCTION_IN_PROGRESS"
        );

        delete nftContractToTokenIdToAuctionId[auction.nftContract][
            auction.tokenId
        ];
        delete auctionIdToAuction[auctionId];

        IERC721(auction.nftContract).transferFrom(
            address(this),
            auction.seller,
            auction.tokenId
        );

        emit ReserveAuctionCanceled(auctionId);
    }

    /**
     * @notice A bidder may place a bid which is at least the value defined by `getMinBidAmount`.
     * If this is the first bid on the auction, the countdown will begin.
     * If there is already an outstanding bid, the previous bidder will be refunded at this time
     * and if the bid is placed in the final moments of the auction, the countdown may be extended.
     */
    function placeBid(
        uint256 amount,
        uint256 auctionId
    ) public payable nonReentrant {
        ReserveAuction storage auction = auctionIdToAuction[auctionId];
        require(
            auction.amount != 0,
            "NFTMarketReserveAuction:AUCTION_NOT_FOUND"
        );
        require(
            auction.startTime <= block.timestamp &&
                auction.endTime >= block.timestamp,
            "NFTMarketReserveAuction:AUCTION_NOT_LIVE"
        );

        uint256 minAmount = _getMinBidAmountForReserveAuction(auction.amount);
        if (auction.paymentMode == address(0)) {
            amount = msg.value;
        }
        require(
            amount >= minAmount,
            "NFTMarketReserveAuction:BID_AMOUNT_TOO_LOW"
        );

        // Cache and update bidder state before a possible reentrancy (via the value transfer)
        uint256 originalAmount = auction.amount;
        address payable originalBidder = auction.bidder;
        if (auction.paymentMode != address(0)) {
            IERC20(auction.paymentMode).transferFrom(
                msg.sender,
                address(this),
                amount
            );
        }
        auction.amount = amount;
        auction.bidder = payable(msg.sender);

        if (originalBidder != address(0)) {
            // Refund the previous bidders
            _sendValueWithFallbackWithdrawWithLowGasLimit(
                auction.paymentMode,
                originalBidder,
                originalAmount
            );
        }

        emit ReserveAuctionBidPlaced(
            auctionId,
            msg.sender,
            amount,
            block.timestamp
        );
    }

    /**
     * @notice Once the countdown has expired for an auction, anyone can settle the auction.
     * This will send the NFT to the highest bidder and distribute funds.
     */
    function finalizeReserveAuction(uint256 auctionId) public nonReentrant {
        ReserveAuction memory auction = auctionIdToAuction[auctionId];
        require(
            auction.endTime > 0,
            "NFTMarketReserveAuction:AUCTION_ALREADY_SETTLED"
        );
        require(
            auction.endTime < block.timestamp,
            "NFTMarketReserveAuction:AUCTION_IN_PROGRESS"
        );

        delete nftContractToTokenIdToAuctionId[auction.nftContract][
            auction.tokenId
        ];
        delete auctionIdToAuction[auctionId];

        IERC721(auction.nftContract).transferFrom(
            address(this),
            auction.bidder,
            auction.tokenId
        );

        (
            uint256 f8nFee,
            uint256 creatorFee,
            uint256 ownerRev
        ) = _distributeFunds(
                auction.paymentMode,
                auction.nftContract,
                auction.tokenId,
                auction.seller,
                auction.amount
            );

        emit ReserveAuctionFinalized(
            auctionId,
            auction.seller,
            auction.bidder,
            f8nFee,
            creatorFee,
            ownerRev
        );
    }

    function getUserTokensOnSale(
        address userAddress,
        address nftContract
    ) public view returns (uint256[] memory) {
        uint256[] memory tokenList = new uint256[](
            userTokensOnSale[userAddress][nftContract].length
        );

        for (
            uint i = 0;
            i < userTokensOnSale[userAddress][nftContract].length;
            i++
        ) {
            if (
                IWHISKYNFT721(nftContract).isExists(
                    userTokensOnSale[userAddress][nftContract][i]
                ) ==
                true &&
                IERC721(nftContract).ownerOf(
                    userTokensOnSale[userAddress][nftContract][i]
                ) ==
                address(this)
            ) tokenList[i] = userTokensOnSale[userAddress][nftContract][i];
        }

        return tokenList;
    }

    /**
     * @notice Returns the minimum amount a bidder must spend to participate in an auction.
     */
    function getMinBidAmount(uint256 auctionId) public view returns (uint256) {
        ReserveAuction storage auction = auctionIdToAuction[auctionId];
        if (auction.endTime < block.timestamp) {
            return auction.amount;
        }
        return _getMinBidAmountForReserveAuction(auction.amount);
    }

    /**
     * @dev Determines the minimum bid amount when outbidding another user.
     */
    function _getMinBidAmountForReserveAuction(
        uint256 currentBidAmount
    ) private view returns (uint256) {
        uint256 minIncrement = currentBidAmount.mul(
            _minPercentIncrementInBasisPoints
        ) / BASIS_POINTS;
        if (minIncrement == 0) {
            // The next bid must be at least 1 wei greater than the current.
            return currentBidAmount.add(1);
        }
        return minIncrement.add(currentBidAmount);
    }

    /**
     * @notice Allows ChronicleVerse to add token address.
     */
    function adminUpdateToken(
        address tokenAddress,
        bool status
    ) public onlyChronicleVerseAdmin {
        tokens[tokenAddress] = status;
        if (tokenAddress == address(0)) {
            emit TokenUpdated(tokenAddress, status);
        } else {
            emit TokenUpdated(tokenAddress, status);
        }
    }

    /**
     * @notice Allows ChronicleVerse to cancel an auction, refunding the bidder and returning the NFT to the seller.
     * This should only be used for extreme cases such as DMCA takedown requests. The reason should always be provided.
     */
    function adminCancelReserveAuction(
        uint256 auctionId,
        string memory reason
    ) public onlyChronicleVerseAdmin {
        require(
            bytes(reason).length > 0,
            "NFTMarketReserveAuction:INCLUDE_A_REASON_FOR_THIS_CANCELLATION"
        );
        ReserveAuction memory auction = auctionIdToAuction[auctionId];
        require(
            auction.amount > 0,
            "NFTMarketReserveAuction:AUCTION_NOT_FOUND"
        );

        delete nftContractToTokenIdToAuctionId[auction.nftContract][
            auction.tokenId
        ];
        delete auctionIdToAuction[auctionId];

        IERC721(auction.nftContract).transferFrom(
            address(this),
            auction.seller,
            auction.tokenId
        );
        if (auction.bidder != address(0)) {
            _sendValueWithFallbackWithdrawWithMediumGasLimit(
                auction.paymentMode,
                auction.bidder,
                auction.amount
            );
        }

        emit ReserveAuctionCanceledByAdmin(auctionId, reason);
    }

    /**
     * @notice Allows an NFT owner and ChronicleVerse to work together in order to update the seller
     * for auctions they have listed to a new account.
     * @param signature Message `I authorize ChronicleVerse to migrate my account to ${newAccount.address.toLowerCase()}`
     * signed by the original account.
     * @dev This will gracefully skip any auctions that have already been finalized.
     */
    function adminAccountMigration(
        uint256[] calldata listedAuctionIds,
        address originalAddress,
        address payable newAddress,
        bytes calldata signature
    )
        public
        onlyAuthorizedAccountMigration(originalAddress, newAddress, signature)
    {
        for (uint256 i = 0; i < listedAuctionIds.length; i++) {
            uint256 auctionId = listedAuctionIds[i];
            ReserveAuction storage auction = auctionIdToAuction[auctionId];
            // The seller would be 0 if it was finalized before this call
            if (auction.seller != address(0)) {
                require(
                    auction.seller == originalAddress,
                    "NFTMarketReserveAuction:AUCTION_NOT_CREATED_BY_THAT_ADDRESS"
                );
                auction.seller = newAddress;
                emit ReserveAuctionSellerMigrated(
                    auctionId,
                    originalAddress,
                    newAddress
                );
            }
        }
    }

}

// File contracts/FNDNFTMarket.sol
pragma abicoder v2; // solhint-disable-line

/**
 * @title A market for NFTs on ChronicleVerse.
 * @dev This top level file holds no data directly to ease future upgrades.
 */
contract ChronicleVerseMarket is
    ChronicleVerseTreasuryNode,
    ChronicleVerseAdminRole,
    ChronicleVerseOperatorRole,
    AccountMigration,
    NFTMarketCore,
    ReentrancyGuard,
    NFTMarketCreators,
    SendValueWithFallbackWithdraw,
    NFTMarketFees,
    NFTMarketAuction,
    NFTMarketReserveAuction,
    NFTMarketPrivateSale
{
    /**
     * @notice Called once to configure the contract after the initial deployment.
     * @dev This farms the initialize call out to inherited contracts as needed.
     */
    constructor(address payable treasury) ChronicleVerseTreasuryNode(treasury) NFTMarketAuction() {}

    /**
     * @notice Allows ChronicleVerse to update the market configuration.
     */
    function adminUpdateConfig(
        uint256 minPercentIncrementInBasisPoints,
        uint256 duration,
        uint256 primaryF8nFeeBasisPoints,
        uint256 secondaryF8nFeeBasisPoints
    ) public onlyChronicleVerseAdmin {
        _reinitialize();
        _updateReserveAuctionConfig(minPercentIncrementInBasisPoints, duration);
        _updateMarketFees(primaryF8nFeeBasisPoints, secondaryF8nFeeBasisPoints);
    }

    /**
     * @dev Checks who the seller for an NFT is, this will check escrow or return the current owner if not in escrow.
     * This is a no-op function required to avoid compile errors.
     */
    function _getSellerFor(
        address nftContract,
        uint256 tokenId
    )
        internal
        view
        virtual
        override(NFTMarketCore, NFTMarketReserveAuction)
        returns (address payable)
    {
        return super._getSellerFor(nftContract, tokenId);
    }
}
