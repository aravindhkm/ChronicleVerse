// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.17;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165Storage.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";


/**
 * @title ERC721 Non-Fungible Token Standard basic implementation
 * @dev see https://eips.ethereum.org/EIPS/eip-721
 */
contract ERC721 is
    Context,
    ERC165Storage,
    IERC721,
    IERC721Metadata,
    IERC721Enumerable
{
    using SafeMath for uint256;
    using Address for address;
    using EnumerableSet for EnumerableSet.UintSet;
    using EnumerableMap for EnumerableMap.UintToAddressMap;
    using Strings for uint256;

    // Equals to `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
    // which can be also obtained as `IERC721Receiver(0).onERC721Received.selector`
    bytes4 private constant _ERC721_RECEIVED = 0x150b7a02;

    // Mapping from holder address to their (enumerable) set of owned tokens
    mapping(address => EnumerableSet.UintSet) private _holderTokens;

    // Enumerable mapping from token ids to their owners
    EnumerableMap.UintToAddressMap private _tokenOwners;

    // Mapping from token ID to approved address
    mapping(uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    //Mapping from tokenId to Royalty
    mapping(uint256 => uint256) internal _tokenRoyaltys;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Optional mapping for token URIs
    mapping(uint256 => string) internal _tokenURIs;

    // Base URI
    string private _baseURI;

    /*
     *     bytes4(keccak256('balanceOf(address)')) == 0x70a08231
     *     bytes4(keccak256('ownerOf(uint256)')) == 0x6352211e
     *     bytes4(keccak256('approve(address,uint256)')) == 0x095ea7b3
     *     bytes4(keccak256('getApproved(uint256)')) == 0x081812fc
     *     bytes4(keccak256('setApprovalForAll(address,bool)')) == 0xa22cb465
     *     bytes4(keccak256('isApprovedForAll(address,address)')) == 0xe985e9c5
     *     bytes4(keccak256('transferFrom(address,address,uint256)')) == 0x23b872dd
     *     bytes4(keccak256('safeTransferFrom(address,address,uint256)')) == 0x42842e0e
     *     bytes4(keccak256('safeTransferFrom(address,address,uint256,bytes)')) == 0xb88d4fde
     *
     *     => 0x70a08231 ^ 0x6352211e ^ 0x095ea7b3 ^ 0x081812fc ^
     *        0xa22cb465 ^ 0xe985e9c5 ^ 0x23b872dd ^ 0x42842e0e ^ 0xb88d4fde == 0x80ac58cd
     */
    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;

    /*
     *     bytes4(keccak256('name()')) == 0x06fdde03
     *     bytes4(keccak256('symbol()')) == 0x95d89b41
     *     bytes4(keccak256('tokenURI(uint256)')) == 0xc87b56dd
     *
     *     => 0x06fdde03 ^ 0x95d89b41 ^ 0xc87b56dd == 0x5b5e139f
     */
    bytes4 private constant _INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;

    /*
     *     bytes4(keccak256('totalSupply()')) == 0x18160ddd
     *     bytes4(keccak256('tokenOfOwnerByIndex(address,uint256)')) == 0x2f745c59
     *     bytes4(keccak256('tokenByIndex(uint256)')) == 0x4f6ccce7
     *
     *     => 0x18160ddd ^ 0x2f745c59 ^ 0x4f6ccce7 == 0x780e9d63
     */
    bytes4 private constant _INTERFACE_ID_ERC721_ENUMERABLE = 0x780e9d63;

    constructor(
        string memory name_,
        string memory symbol_
    ) {
        _name = name_;
        _symbol = symbol_;

        _registerInterface(_INTERFACE_ID_ERC721);
        _registerInterface(_INTERFACE_ID_ERC721_METADATA);
        _registerInterface(_INTERFACE_ID_ERC721_ENUMERABLE);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view override returns (uint256) {
        require(
            owner != address(0),
            "ERC721: balance query for the zero address"
        );

        return _holderTokens[owner].length();
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view override returns (address) {
        return
            _tokenOwners.get(
                tokenId,
                "ERC721: owner query for nonexistent token"
            );
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        require(
            _exists(tokenId),
            "ERC721Metadata: URI query for nonexistent token"
        );

        string memory _tokenURI = _tokenURIs[tokenId];

        // If there is no base URI, return the token URI.
        if (bytes(_baseURI).length == 0) {
            return _tokenURI;
        }
        // If both are set, concatenate the baseURI and tokenURI (via abi.encodePacked).
        if (bytes(_tokenURI).length > 0) {
            return string(abi.encodePacked(_baseURI, _tokenURI));
        }
        // If there is a baseURI but no tokenURI, concatenate the tokenID to the baseURI.
        return string(abi.encodePacked(_baseURI, tokenId.toString()));
    }

    /**
     * @dev Returns the base URI set via {_setBaseURI}. This will be
     * automatically added as a prefix in {tokenURI} to each token's URI, or
     * to the token ID if no specific URI is set for that token ID.
     */
    function baseURI() public view returns (string memory) {
        return _baseURI;
    }

    /**
     * @dev See {IERC721Enumerable-tokenOfOwnerByIndex}.
     */
    function tokenOfOwnerByIndex(
        address owner,
        uint256 index
    ) public view override returns (uint256) {
        return _holderTokens[owner].at(index);
    }

    /**
     * @dev See {IERC721Enumerable-totalSupply}.
     */
    function totalSupply() public view override returns (uint256) {
        // _tokenOwners are indexed by tokenIds, so .length() returns the number of tokenIds
        return _tokenOwners.length();
    }

    /**
     * @dev See {IERC721Enumerable-tokenByIndex}.
     */
    function tokenByIndex(
        uint256 index
    ) public view override returns (uint256) {
        (uint256 tokenId, ) = _tokenOwners.at(index);
        return tokenId;
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(
        uint256 tokenId
    ) public view override returns (address) {
        require(
            _exists(tokenId),
            "ERC721: approved query for nonexistent token"
        );

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(
        address operator,
        bool approved
    ) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(
        address owner,
        address operator
    ) public view override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        //solhint-disable-next-line max-line-length
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(
            _checkOnERC721Received(from, to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view returns (bool) {
        return _tokenOwners.contains(tokenId);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(
        address spender,
        uint256 tokenId
    ) internal view returns (bool) {
        require(
            _exists(tokenId),
            "ERC721: operator query for nonexistent token"
        );
        address owner = ownerOf(tokenId);
        return (spender == owner ||
            getApproved(tokenId) == spender ||
            isApprovedForAll(owner, spender));
    }

    /**
        * @dev Safely mints `tokenId` and transfers it to `to`.
        *
        * Requirements:
        d*
        * - `tokenId` must not exist.
        * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
        *
        * Emits a {Transfer} event.
        */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _holderTokens[to].add(tokenId);

        _tokenOwners.set(tokenId, to);
        //Supply has to be incremented
        emit Transfer(address(0), to, tokenId);
    }

    /**
     * @dev sets royalty for tokenId
     */
    function _setTokenRoyalty(uint256 tokenId, uint256 royalty) internal {
        _tokenRoyaltys[tokenId] = royalty;
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual {
        address owner = ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);

        // Clear metadata (if any)
        if (bytes(_tokenURIs[tokenId]).length != 0) {
            delete _tokenURIs[tokenId];
        }

        _holderTokens[owner].remove(tokenId);

        _tokenOwners.remove(tokenId);
        //decrement supply

        emit Transfer(owner, address(0), tokenId);
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(
            ownerOf(tokenId) == from,
            "ERC721: transfer of token that is not own"
        );
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _holderTokens[from].remove(tokenId);
        _holderTokens[to].add(tokenId);

        _tokenOwners.set(tokenId, to);

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _setTokenURI(
        uint256 tokenId,
        string memory _tokenURI
    ) internal virtual {
        _tokenURIs[tokenId] = _tokenURI;
    }

    /**
     * @dev Internal function to set the base URI for all token IDs. It is
     * automatically added as a prefix to the value returned in {tokenURI},
     * or to the token ID if {tokenURI} is empty.
     */
    function _setBaseURI(string memory baseURI_) internal virtual {
        _baseURI = baseURI_;
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (!to.isContract()) {
            return true;
        }
        bytes memory returndata = to.functionCall(
            abi.encodeWithSelector(
                IERC721Receiver(to).onERC721Received.selector,
                _msgSender(),
                from,
                tokenId,
                _data
            ),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
        bytes4 retval = abi.decode(returndata, (bytes4));
        return (retval == _ERC721_RECEIVED);
    }

    function _approve(address to, uint256 tokenId) private {
        _tokenApprovals[tokenId] = to;
        emit Approval(ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}

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

// File contracts/mixins/HasSecondarySaleFees.sol



/**
 * @notice An interface for communicating fees to 3rd party marketplaces.
 * @dev Originally implemented in mainnet contract 0x44d6e8933f8271abcf253c72f9ed7e0e4c0323b3
 */
abstract contract HasSecondarySaleFees is ERC165Storage {
    /*
     * bytes4(keccak256('getFeeBps(uint256)')) == 0x0ebd4c7f
     * bytes4(keccak256('getFeeRecipients(uint256)')) == 0xb9c4d9fb
     *
     * => 0x0ebd4c7f ^ 0xb9c4d9fb == 0xb7799584
     */
    bytes4 private constant _INTERFACE_ID_FEES = 0xb7799584;

    /**
     * @dev Called once after the initial deployment to register the interface with ERC165.
     */
    constructor() {
        _registerInterface(_INTERFACE_ID_FEES);
    }

    function getFeeRecipients(
        uint256 id
    ) public view virtual returns (address payable[] memory);

    function getFeeBps(
        address nftMarket,
        uint256 id
    ) public view virtual returns (uint256[] memory);
}



// File contracts/interfaces/IFNDNFTMarket.sol

// solhint-disable



interface IFNDNFTMarket {
    function getFeeConfig(
        address,
        uint256
    )
        external
        view
        returns (
            uint256 primaryF8nFeeBasisPoints,
            uint256 secondaryF8nFeeBasisPoints,
            uint256 secondaryCreatorFeeBasisPoints
        );

    function getChronicleVerseFees()
        external
        view
        returns (
            uint256 primaryChronicleVerseFeeBasisPoints,
            uint256 secondaryChronicleVerseFeeBasisPoints
        );
}



// File contracts/mixins/NFT721Creator.sol



/**
 * @notice Allows each token to be associated with a creator.
 */
abstract contract NFT721Creator is ERC721 {
    mapping(uint256 => address payable) private tokenIdToCreator;

    /**
     * @dev Stores an optional alternate address to receive creator revenue and royalty payments.
     */
    mapping(uint256 => address payable) private tokenIdToCreatorPaymentAddress;

    event TokenCreatorUpdated(
        address indexed fromCreator,
        address indexed toCreator,
        uint256 indexed tokenId
    );
    event TokenCreatorPaymentAddressSet(
        address indexed fromPaymentAddress,
        address indexed toPaymentAddress,
        uint256 indexed tokenId
    );
    /*
     * bytes4(keccak256('tokenCreator(uint256)')) == 0x40c1a064
     */
    bytes4 private constant _INTERFACE_TOKEN_CREATOR = 0x40c1a064;

    /*
     * bytes4(keccak256('getTokenCreatorPaymentAddress(uint256)')) == 0xec5f752e;
     */
    bytes4 private constant _INTERFACE_TOKEN_CREATOR_PAYMENT_ADDRESS =
        0xec5f752e;

    modifier onlyCreatorAndOwner(uint256 tokenId) {
        require(
            tokenIdToCreator[tokenId] == msg.sender,
            "NFT721Creator: Caller is not creator"
        );
        require(
            ownerOf(tokenId) == msg.sender,
            "NFT721Creator: Caller does not own the NFT"
        );
        _;
    }

    /**
     * @dev Called once after the initial deployment to register the interface with ERC165.
     */
    function _initializeNFT721Creator() internal  {
        _registerInterface(_INTERFACE_TOKEN_CREATOR);
    }
    /**
     * @notice Allows ERC165 interfaces which were not included originally to be registered.
     * @dev Currently this is the only new interface, but later other mixins can overload this function to do the same.
     */
    function registerInterfaces() public {
        _registerInterface(_INTERFACE_TOKEN_CREATOR_PAYMENT_ADDRESS);
    }


    /**
     * @notice Returns the creator's address for a given tokenId.
     */
    function tokenCreator(
        uint256 tokenId
    ) public view returns (address payable) {
        return tokenIdToCreator[tokenId];
    }

    /**
     * @notice Returns the payment address for a given tokenId.
     * @dev If an alternate address was not defined, the creator is returned instead.
     */
    function getTokenCreatorPaymentAddress(
        uint256 tokenId
    ) public view returns (address payable tokenCreatorPaymentAddress) {
        tokenCreatorPaymentAddress = tokenIdToCreatorPaymentAddress[tokenId];
        if (tokenCreatorPaymentAddress == address(0)) {
            tokenCreatorPaymentAddress = tokenIdToCreator[tokenId];
        }
    }

    function _updateTokenCreator(
        uint256 tokenId,
        address payable creator
    ) internal {
        emit TokenCreatorUpdated(tokenIdToCreator[tokenId], creator, tokenId);

        tokenIdToCreator[tokenId] = creator;
    }

    /**
     * @dev Allow setting a different address to send payments to for both primary sale revenue
     * and secondary sales royalties.
     */
    function _setTokenCreatorPaymentAddress(
        uint256 tokenId,
        address payable tokenCreatorPaymentAddress
    ) internal {
        emit TokenCreatorPaymentAddressSet(
            tokenIdToCreatorPaymentAddress[tokenId],
            tokenCreatorPaymentAddress,
            tokenId
        );
        tokenIdToCreatorPaymentAddress[tokenId] = tokenCreatorPaymentAddress;
    }

    /**
     * @notice Allows the creator to burn if they currently own the NFT.
     */
    function burn(uint256 tokenId) public onlyCreatorAndOwner(tokenId) {
        _burn(tokenId);
    }

    function isExists(uint tokenId) public view returns(bool) {
       return _exists(tokenId);
    }

    /**
     * @dev Remove the creator record when burned.
     */
    function _burn(uint256 tokenId) internal virtual override {
        delete tokenIdToCreator[tokenId];

        super._burn(tokenId);
    }

}

// File contracts/mixins/NFT721Market.sol



/**
 * @notice Holds a reference to the ChronicleVerse Market and communicates fees to 3rd party marketplaces.
 */
abstract contract NFT721Market is
    ChronicleVerseTreasuryNode,
    HasSecondarySaleFees,
    NFT721Creator
{
    using Address for address;

    /**
     * @notice Returns an array of recipient addresses to which fees should be sent.
     * The expected fee amount is communicated with `getFeeBps`.
     */
    function getFeeRecipients(
        uint256 id
    ) public view override returns (address payable[] memory) {
        require(_exists(id), "ERC721Metadata:nonexistent token");

        address payable[] memory result = new address payable[](2);
        result[0] = getChronicleVerseTreasury();
        result[1] = getTokenCreatorPaymentAddress(id);
        return result;
    }

    /**
     * @notice Returns an array of fees in basis points.
     * The expected recipients is communicated with `getFeeRecipients`.
     */
    function getFeeBps(
        address nftMarket,
        uint256 tokenId
    ) public view override returns (uint256[] memory) {
        (
            ,
            uint256 secondaryF8nFeeBasisPoints,
            uint256 secondaryCreatorFeeBasisPoints
        ) = IFNDNFTMarket(nftMarket).getFeeConfig(address(this), tokenId);
        uint256[] memory result = new uint256[](2);
        result[0] = secondaryF8nFeeBasisPoints;
        result[1] = secondaryCreatorFeeBasisPoints;
        return result;
    }

    /**
     * @notice Get fee recipients and fees in a single call.
     * The data is the same as when calling getFeeRecipients and getFeeBps separately.
     */
    function getFees(
        address nftMarket,
        uint256 tokenId
    )
        public
        view
        returns (
            address payable[2] memory recipients,
            uint256[2] memory feesInBasisPoints
        )
    {
        require(_exists(tokenId), "ERC721Metadata:nonexistent token");

        recipients[0] = getChronicleVerseTreasury();
        recipients[1] = getTokenCreatorPaymentAddress(tokenId);
        (
            ,
            uint256 secondaryF8nFeeBasisPoints,
            uint256 secondaryCreatorFeeBasisPoints
        ) = IFNDNFTMarket(nftMarket).getFeeConfig(address(this), tokenId);
        feesInBasisPoints[0] = secondaryF8nFeeBasisPoints;
        feesInBasisPoints[1] = secondaryCreatorFeeBasisPoints;
    }

}

// File contracts/mixins/NFT721Metadata.sol



/**
 * @notice A mixin to extend the OpenZeppelin metadata implementation.
 */
abstract contract NFT721Metadata is NFT721Creator {
    /**
     * @dev Stores hashes minted by a creator to prevent duplicates.
     */
    mapping(address => mapping(string => bool))
        private creatorToIPFSHashToMinted;

    event TokenIPFSPathUpdated(
        uint256 indexed tokenId,
        string indexed indexedTokenIPFSPath,
        string tokenIPFSPath
    );
    // This event was used in an order version of the contract
    event NFTMetadataUpdated(string name, string symbol, string baseURI);

    /**
     * @notice Returns the IPFSPath to the metadata JSON file for a given NFT.
     */
    function getTokenIPFSPath(
        uint256 tokenId
    ) public view returns (string memory) {
        return _tokenURIs[tokenId];
    }

    /**
     * @notice Checks if the creator has already minted a given NFT.
     */
    function getHasCreatorMintedIPFSHash(
        address creator,
        string memory tokenIPFSPath
    ) public view returns (bool) {
        return creatorToIPFSHashToMinted[creator][tokenIPFSPath];
    }

    /**
     * @notice Returns the royalty for a given tokenId
     */
    function getTokenRoyalty(uint256 tokenId) public view returns (uint256) {
        return _tokenRoyaltys[tokenId];
    }

    function _updateBaseURI(string memory _baseURI) internal {
        _setBaseURI(_baseURI);
    }

    /**
     * @dev The IPFS path should be the CID + file.extension, e.g.
     * `QmfPsfGwLhiJrU8t9HpG4wuyjgPo9bk8go4aQqSu9Qg4h7/metadata.json`
     */
    function _setTokenIPFSPath(
        uint256 tokenId,
        string memory _tokenIPFSPath
    ) internal {
        // 46 is the minimum length for an IPFS content hash, it may be longer if paths are used
        require(
            bytes(_tokenIPFSPath).length >= 46,
            "NFT721Metadata: Invalid IPFS path"
        );
        require(
            !creatorToIPFSHashToMinted[msg.sender][_tokenIPFSPath],
            "NFT721Metadata: NFT was already minted"
        );
        if (creatorToIPFSHashToMinted[msg.sender][getTokenIPFSPath(tokenId)])
            creatorToIPFSHashToMinted[msg.sender][
                getTokenIPFSPath(tokenId)
            ] = false;

        creatorToIPFSHashToMinted[msg.sender][_tokenIPFSPath] = true;
        _setTokenURI(tokenId, _tokenIPFSPath);
    }

    /**
     * @dev When a token is burned, remove record of it allowing that creator to re-mint the same NFT again in the future.
     */
    function _burn(uint256 tokenId) internal virtual override {
        delete creatorToIPFSHashToMinted[msg.sender][_tokenURIs[tokenId]];
        super._burn(tokenId);
    }

}

// File contracts/mixins/NFT721Mint.sol



/**
 * @notice Allows creators to mint NFTs.
 */
abstract contract NFT721Mint is
    ERC721,
    NFT721Creator,
    NFT721Market,
    NFT721Metadata,
    ChronicleVerseAdminRole
{
    // using AddressLibrary for address;
    address private collectionCreator;
    uint256 private nextTokenId = 1;
    using SafeMath for uint256;

    event Minted(
        address indexed creator,
        uint256 indexed tokenId,
        string indexed indexedTokenIPFSPath,
        string tokenIPFSPath,
        uint256 royalty,
        address marketContract
    );

    event Updated(
        address indexed creator,
        uint256 indexed tokenId,
        string indexed indexedTokenIPFSPath,
        string tokenIPFSPath
    );

    /**
     * @notice Gets the tokenId of the next NFT minted.
     */
    function getNextTokenId() public view returns (uint256) {
        return nextTokenId;
    }

    /**
     * @notice Allows a creator to mint an NFT.
     */
    function mint(
        string memory tokenIPFSPath,
        uint256 royalty,
        address marketContract
    ) public returns (uint256 tokenId) {
        (, uint256 secondaryF8nFeeBasisPoints) = IFNDNFTMarket(marketContract)
            .getChronicleVerseFees();

        require(
            secondaryF8nFeeBasisPoints.add(royalty) < 10000,
            "Fees >= 100%"
        );

        tokenId = nextTokenId++;

        _setTokenRoyalty(tokenId, royalty);
        _mint(msg.sender, tokenId);
        _updateTokenCreator(tokenId, payable(msg.sender));
        _setTokenIPFSPath(tokenId, tokenIPFSPath);
        emit Minted(
            msg.sender,
            tokenId,
            tokenIPFSPath,
            tokenIPFSPath,
            royalty,
            marketContract
        );
    }

    /**
     * @notice Allows a creator to mint an NFT and set approval for the ChronicleVerse marketplace.
     * This can be used by creators the first time they mint an NFT to save having to issue a separate
     * approval transaction before starting an auction.
     */
    function mintAndApproveMarket(
        string memory tokenIPFSPath,
        uint256 royalty,
        address marketContract
    ) public returns (uint256 tokenId) {
        tokenId = mint(tokenIPFSPath, royalty, marketContract);
        setApprovalForAll(marketContract, true);
    }

    /**
     * @notice Allows a creator to mint an NFT and have creator revenue/royalties sent to an alternate address.
     */
    function mintWithCreatorPaymentAddress(
        string memory tokenIPFSPath,
        address payable tokenCreatorPaymentAddress,
        uint256 royalty,
        address marketContract
    ) public returns (uint256 tokenId) {
        require(
            tokenCreatorPaymentAddress != address(0),
            "NFT721Mint:TOKEN_CREATOR_PAYMENT_ADDRESS_IS_REQUIRED"
        );
        tokenId = mint(tokenIPFSPath, royalty, marketContract);
        _setTokenCreatorPaymentAddress(tokenId, tokenCreatorPaymentAddress);
    }

    /**
     * @notice Allows a creator to mint an NFT and have creator revenue/royalties sent to an alternate address.
     * Also sets approval for the ChronicleVerse marketplace.  This can be used by creators the first time they mint an NFT to
     * save having to issue a separate approval transaction before starting an auction.
     */
    function mintWithCreatorPaymentAddressAndApproveMarket(
        string memory tokenIPFSPath,
        address payable tokenCreatorPaymentAddress,
        uint256 royalty,
        address marketContract
    ) public returns (uint256 tokenId) {
        tokenId = mintWithCreatorPaymentAddress(
            tokenIPFSPath,
            tokenCreatorPaymentAddress,
            royalty,
            marketContract
        );
        setApprovalForAll(marketContract, true);
    }

    /**
     * @notice Allows a creator to update an NFT IPFS path.
     */
    function updateTokenURI(
        uint256 tokenId,
        string memory tokenIPFSPath
    ) public {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "NFT721Mint:ADDRESS_NOT_AUTHORIZED");
        _setTokenIPFSPath(tokenId, tokenIPFSPath);
        emit Updated(msg.sender, tokenId, tokenIPFSPath, tokenIPFSPath);
    }

    /**
     * @dev Explicit override to address compile errors.
     */
    function _burn(
        uint256 tokenId
    )
        internal
        virtual
        override(ERC721, NFT721Creator, NFT721Metadata)
    {
        super._burn(tokenId);
    }

}

// File contracts/FNDNFT721.sol



/**
 * @title ChronicleVerse NFTs implemented using the ERC-721 standard.
 * @dev This top level file holds no data directly to ease future upgrades.
 */
contract ChronicleVerseNFT is
    ChronicleVerseTreasuryNode,
    HasSecondarySaleFees,
    ERC721,
    NFT721Creator,
    NFT721Market,
    NFT721Metadata,
    NFT721Mint
{
    /**
     * @notice Called once to configure the contract after the initial deployment.
     * @dev This farms the initialize call out to inherited contracts as needed.
     */
    constructor(
        address payable treasury,
        string memory name,
        string memory symbol, 
        string memory baseURI
    ) ERC721(name, symbol) ChronicleVerseTreasuryNode(treasury) {
        NFT721Creator._initializeNFT721Creator();
        _updateBaseURI(baseURI);
    }

    // /**
    //  * @notice Allows a ChronicleVerse admin to update NFT config variables.
    //  * @dev This must be called right after the initial call to `initialize`.
    //  */
    // function adminUpdateConfig(
    //     string memory baseURI
    // ) public onlyChronicleVerseAdmin {
    //     _updateBaseURI(baseURI);
    // }

    /**
     * @dev This is a no-op, just an explicit override to address compile errors due to inheritance.
     */
    function _burn(
        uint256 tokenId
    )
        internal
        virtual
        override(ERC721, NFT721Creator, NFT721Metadata, NFT721Mint)
    {
        super._burn(tokenId);
    }
}
