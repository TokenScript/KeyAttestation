// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Context.sol";

import { EMPTY_UID, EIP712Signature, Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { IEAS, RevocationRequest, RevocationRequestData } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

library _AddressUtil {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}

interface IERC5169 {
    /// @dev This event emits when the scriptURI is updated, 
    /// so wallets implementing this interface can update a cached script
    event ScriptUpdate(string newScriptURI);

    /// @notice Get the scriptURI for the contract
    /// @return The scriptURI
    function scriptURI() external view returns(string memory);
	
    /// @notice Update the scriptURI
    /// emits event ScriptUpdate(string memory newScriptURI);
    function updateScriptURI(string memory newScriptURI) external;
}

contract KeyResolver is SchemaResolver, ERC721Enumerable, IERC5169, Ownable {

    address public attester;
    using Strings for uint256;

    bytes32 private constant tokenIdMask        = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000;

    string private constant _baseTokenMetadataURI = "http://smarttokenlabs.duckdns.org:8081/keymetadata/";

    string private _scriptURI;

    string private constant _contractURI = "ipfs://QmY6D8ga9hvSKqAxXntU7xi58fmgKoD99T51zT8eSSGqbL";

    mapping(bytes32 => bytes32[]) rootKeyMap;
    mapping(uint256 => bytes32) tokenIdUIDMap;

    constructor(IEAS eas) SchemaResolver(eas) ERC721("Key Attestations", "ATTN") {
        attester = msg.sender;
    }

    /// @notice Updates the attester for future
    /// @param newAttester The new attester address to be set in the contract state.

    function updateAttester(address newAttester) external {
        if (msg.sender != attester) revert();
        attester = newAttester;
    }

    function getEAS() external view returns (IEAS) {
        return _eas;
    }

    /// @notice Called by EAS Contracts if a schema has resolver set while attesting.
    /// @param attestation The attestation calldata forwarded by EAS Contracts.
    /// @return returns bool to have custom logic to accept or reject an attestation.

    function onAttest(
        Attestation calldata attestation,
        uint256
    ) internal virtual override returns (bool) {
        uint256 tokenId;
        // Root attestation or derivative key?
        if (attestation.refUID == bytes32(0)) //Note; the smart contract is passed the root UID for validation
        {
            //Declare as NFT
            tokenId = rootTokenId(attestation.uid);
            require(rootKeyMap[attestation.uid].length == 0, "Attestation already exists");
            _mint(attestation.attester, tokenId);
            rootKeyMap[attestation.uid].push(attestation.uid);
        }
        else //can only be called by root key owner or creator
        {
            tokenId = rootTokenId(attestation.refUID);
            Attestation memory rootAttestation = _eas.getAttestation(attestation.refUID);
            require (attestation.attester == rootAttestation.attester || attestation.attester == ownerOf(tokenId), "Derivative key can only be created by root key owner"); //derivative can be issued by attestation root key or owner of root key NFT
            tokenId += rootKeyMap[attestation.refUID].length;
            _mint(attestation.recipient, tokenId);
            rootKeyMap[attestation.refUID].push(attestation.uid);
        }

        tokenIdUIDMap[tokenId] = attestation.uid;

        //metadata is sourced from website
        return true;
    }

    /// @notice Called by EAS Contracts if a schema has resolver set while revoking attestations.
    /// @return returns bool to have custom logic to accept or reject a revoke request.

    function onRevoke(
        Attestation calldata /*attestation*/,
        uint256 /*value*/
    ) internal virtual override returns (bool) {
        return true;
    }

    function contractURI() public pure returns (string memory) {
        return _contractURI;
    }

    /// @notice Returns the metadata for given ID
    /// @param id The ID for which the metadata is to be returned
    /// @return Returns the metadata for given ID

    function tokenURI(uint256 id) public view virtual override returns (string memory) {
        require(_exists(id), "Token does not exist");
        bytes32 uid = tokenIdUIDMap[id];
        Attestation memory attestation = _eas.getAttestation(uid);  

        (
            string memory name
            ,
            ,
        ) = abi.decode(
                attestation.data,
                (
                    string,
                    bytes,
                    bytes
                )
            );

         return string(abi.encodePacked(_baseTokenMetadataURI, block.chainid.toString(), "/", contractAddress(), "?tokenId=", id.toHexString(), 
            "&uid=", tokenIdToUID(id).toHexString(), "&name=", name, getValidityData(attestation)));
    }

    function getValidityData(Attestation memory attestation) private view returns (string memory) {
        Attestation memory rootAttn = _eas.getAttestation(attestation.refUID);
        uint64 revocationTime = attestation.revocationTime;
        if (rootAttn.revocationTime > 0 && revocationTime == 0) { //Take into account the root key being revoked
            revocationTime = rootAttn.revocationTime;
        }
        return string(abi.encodePacked("&isValid=", getAttestationValidityText(attestation), "&timestamp=", uint256(attestation.time).toString(), 
            "&expirationTime=", uint256(attestation.expirationTime).toString(),
            "&revocationTime=", uint256(revocationTime).toString()));
    }

    function tokenIdToUID(uint256 id) private view returns (uint256) {
        require(_exists(id), "Token does not exist");
        return uint256(tokenIdUIDMap[id]);
    }

    function tokenIdToAttestation(uint256 id) public view returns (Attestation memory) {
        require(_exists(id), "Token does not exist");
        return _eas.getAttestation(tokenIdUIDMap[id]);
    }

    function getAttestation(bytes32 uid) public view returns (Attestation memory) {
        return _eas.getAttestation(uid);
    }

    function getAttestationValidityText(Attestation memory attestation) private view returns (string memory) {
        if (isKeyValid(attestation) && isKeyValid(_eas.getAttestation(attestation.refUID))) {
            return "true";
        } else {
            return "false";
        }
    }

    function isPayable() public pure virtual override returns (bool) {
        return true;
    }

    function contractAddress() internal view returns (string memory) {
        return Strings.toHexString(uint160(address(this)), 20);
    }

    function validateSignature(bytes32 rootUID, address signer) public view returns (bool) {
        // Walk the keys for this rootUID and see if any match and haven't been revoked
        //now check derivative keys
        Attestation memory rootAttn = _eas.getAttestation(rootUID); 
        for (uint256 i = 0; i < rootKeyMap[rootUID].length; i++) {
            bytes32 thisUID = rootKeyMap[rootUID][i];
            Attestation memory thisAttn = _eas.getAttestation(thisUID);
            if (signer == getSigningAddressFromAttestation(thisAttn) && isKeyValid(thisAttn) && isKeyValid(rootAttn)) { //keep checking all keys until true or we run out
                return true;
            }
        }

        return false;
    }

    function isKeyValid(Attestation memory attn) public view returns (bool) {
        //check expiry time and revocation time
        return attn.revocationTime == 0 && (attn.expirationTime == 0 || block.timestamp < attn.expirationTime);
    }

    function getValidSigningAddresses(bytes32 rootUID) public view returns (address[] memory signingKeys, bytes32[] memory uids) {
        uint size = 0;
        Attestation memory rootAttn = _eas.getAttestation(rootUID);
        for (uint256 i = 0; i < rootKeyMap[rootUID].length; i++) {
            if (isKeyValid(_eas.getAttestation(rootKeyMap[rootUID][i])) && isKeyValid(rootAttn)) {
                size++;
            }
        }

        signingKeys = new address[](size);
        uids = new bytes32[](size);

        uint index = 0;
        for (uint256 i = 0; i < rootKeyMap[rootUID].length; i++) {
            Attestation memory attn = _eas.getAttestation(rootKeyMap[rootUID][i]);
            if (isKeyValid(attn) && isKeyValid(rootAttn)) {
                signingKeys[index] = getSigningAddressFromAttestation(attn);
                uids[index] = attn.uid;
                unchecked {
                    index++;
                }
            }
        }
    }

    function getRevocationRequest(Attestation memory attestation) private pure returns (RevocationRequest memory) {
        return RevocationRequest(attestation.schema, RevocationRequestData(attestation.uid, 0));
    }

    /*****
    * Transfer overrides
    *
    *****/
    function burnToken(uint256 tokenId) public {
        require(_exists(tokenId), "burn: nonexistent token");
        require(ownerOf(tokenId) == msg.sender, "burn: not owned");
        //burn token and revoke attestation. If root, it will completely revoke all derivatives
        //revoke associated attestation
        bytes32 uid = tokenIdUIDMap[tokenId];
        Attestation memory attestation = _eas.getAttestation(uid);
        //is this root attestation?
        if (attestation.uid != bytes32(0) && attestation.refUID == bytes32(0)) {
            if (msg.sender == attestation.attester) {
                //revoke root
                _eas.revoke(getRevocationRequest(attestation));
            } else {
                //transfer back to root attester, no burn
                _transfer(msg.sender, attestation.attester, tokenId);
                return;
            }
        } else { //this is derived attestation, revoke
            _eas.revoke(getRevocationRequest(attestation));
        }

        //burn token
        _burn(tokenId);
    }

    // Only allow root owner to transfer tokens
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public override(ERC721, IERC721) onlyOwner {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        Attestation memory attestation = _eas.getAttestation(tokenIdUIDMap[tokenId]);
        require(attestation.refUID == bytes32(0), "Only root token can be transferred");
        require(attestation.attester == msg.sender, "Only original root owner can transfer");
        _safeTransfer(from, to, tokenId, _data);
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override(ERC721, IERC721) onlyOwner {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        Attestation memory attestation = _eas.getAttestation(tokenIdUIDMap[tokenId]);
        require(attestation.refUID == bytes32(0), "Only root token can be transferred");
        require(attestation.attester == msg.sender, "Only original root owner can transfer");
        _transfer(from, to, tokenId);
    }

    //Original root key issuer should be able to transfer the root key back to the account (eg lost key)
    function recoverRootKey(
        bytes32 uid
    ) public virtual {
        //recover root attestation
        Attestation memory attestation = _eas.getAttestation(uid);

        //Only root key is recoverable, also check this UID exists as a root key attestation
        require(attestation.refUID == bytes32(0) && attestation.uid == uid && uid != bytes32(0), "Only root key attestation is recoverable, use revoke for derivative keys");

        //match attestation owner
        require(attestation.attester == msg.sender, "Only recoverable by root key creator");

        uint256 id = rootTokenId(attestation.uid);

        //recover key NFT to original address
        require(ownerOf(id) != msg.sender, "Recovery not required");

        _transfer(ownerOf(id), msg.sender, id);
    }

    //ERC5169
    function scriptURI() public view override returns (string memory) {
        return _scriptURI;
    }

    function updateScriptURI(string memory newScriptURI) public override onlyOwner {
        _scriptURI = newScriptURI;
        emit ScriptUpdate(newScriptURI);
    }

    //Utility functions
    function getSigningAddressFromAttestation(Attestation memory attn) private pure returns (address keyAddr) {
        (
            //key schema is: 
            //String name
            //Bytes ASN1 Key
            //Bytes public key
            ,
            ,
            bytes memory publicKey
        ) = abi.decode(
                attn.data,
                (
                    string,
                    bytes,
                    bytes
                )
            );

        keyAddr = publicKeyToAddress(publicKey);
    }

    function publicKeyToAddress(bytes memory publicKey) pure internal returns(address keyAddr)
    {
        bytes32 keyHash = keccak256(publicKey);
        bytes memory scratch = new bytes(32);

        assembly {
            mstore(add(scratch, 32), keyHash)
            mstore(add(scratch, 12), 0)
            keyAddr := mload(add(scratch, 32))
        }
    } 

    //TokenID top 27 bytes is UID, mask off lower bytes for individual tokenId
    function rootTokenId(bytes32 uid) private pure returns (uint256) {
        return uint256(uid & tokenIdMask) + 1;
    }

}