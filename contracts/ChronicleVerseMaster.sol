// SPDX-License-Identifier: UNLICENSED
import "./ChronicleVerseNFT.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

pragma solidity 0.8.17;
pragma abicoder v2;

contract ChronicleVerseMaster is Ownable{

    struct CollectionInfo {
        // the collection symbol
        string name;
        // the collection matadate
        string ipfsHash;
        // the contract address
        address newCollection;
    }

    // collection info mapping
    mapping(address => mapping(address => CollectionInfo)) public collections;
    // get collection
    mapping(address => mapping(string => address)) public getCollection;
    // get collection code with address
    mapping(address => address[]) public userCollection;

    mapping (address => bool) public whiteListStatus;

    address payable public chronicleVerseTreasury;

    event CollectionCreated(
        address creator,
        string colCode,
        address newCollection
    );

    constructor(address payable treasury) {
        chronicleVerseTreasury = treasury;
    }

    function setWhiteList(address[] memory accounts,bool status) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            whiteListStatus[accounts[i]] = status;
        }
    }

    /**
     * @notice Allows admin to create a collection.
     */
    function createCollection(
        string memory _name,
        string memory _ipfsHash
    ) external returns (address collection) {
        require(
            whiteListStatus[msg.sender],
            "Caller is not the whitelister"
        );
        require(
            getCollection[msg.sender][_name] == address(0),
            "Collection Master : COLLECTION_EXISTS"
        );

        bytes32 salt = keccak256(abi.encode(_name, _name, "https://ipfs.io/ipfs/"));

        collection = address(new ChronicleVerseNFT{salt: salt}(chronicleVerseTreasury, _name, _name, "https://ipfs.io/ipfs/"));

        getCollection[msg.sender][_name] = collection;
        userCollection[msg.sender].push(collection);

        collections[msg.sender][collection] = CollectionInfo({
            name: _name,
            ipfsHash: _ipfsHash,
            newCollection: collection
        });

        emit CollectionCreated(msg.sender, _name, collection);
    }

    function userCollections(
        address userAddress
    ) public view returns (CollectionInfo[] memory) {
        address[] memory collectionList = new address[](
            userCollection[userAddress].length
        );
        for (uint i = 0; i < userCollection[userAddress].length; i++) {
            collectionList[i] = userCollection[userAddress][i];
        }
        CollectionInfo[] memory collectionInfos = new CollectionInfo[](
            collectionList.length
        );
        for (uint i = 0; i < collectionList.length; i++) {
            CollectionInfo storage infos = collections[userAddress][
                collectionList[i]
            ];
            collectionInfos[i] = infos;
        }
        return collectionInfos;
    }
}
