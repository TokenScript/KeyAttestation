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

import { ERC5169 } from "stl-contracts/ERC/ERC5169.sol";
import "./interface/IKeyResolver.sol";

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

contract KeyResolver is IKeyResolver, SchemaResolver, ERC721Enumerable, ERC5169, Ownable {

    address public attester;
    using Strings for uint256;

    bytes32 private constant TOKEN_ID_MASK        = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000;

    string private constant BASE_TOKEN_METADATA_URI = "http://smarttokenlabs.duckdns.org:8081/keymetadata/";

    string private constant CONTRACT_URI = "ipfs://QmY6D8ga9hvSKqAxXntU7xi58fmgKoD99T51zT8eSSGqbL";

    // in current case its not a root key MAP, but all key MAP, where first ID is main
    mapping(bytes32 => bytes32[]) rootKeyMap;

    constructor(IEAS eas) SchemaResolver(eas) ERC721("Key Attestations", "ATTN") {
        attester = msg.sender;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721Enumerable, ERC5169) returns (bool) {
        return
            ERC5169.supportsInterface(interfaceId) ||
            ERC721Enumerable.supportsInterface(interfaceId);
    }

    function _authorizeSetScripts(string[] memory newScriptURI) internal virtual override onlyOwner {}

    /// @notice Updates the attester for future
    /// @param newAttester The new attester address to be set in the contract state.

    function updateAttester(address newAttester) external {
        if (msg.sender != attester) revert();
        if (address(0) == newAttester) revert("Address required");
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
    // TODO test if internal OK here? if should not work
    ) internal virtual override returns (bool) {
        uint256 tokenId;
        // Root attestation or derivative key?
        if (attestation.refUID == bytes32(0)) //Note; the smart contract is passed the root UID for validation
        {
            //Declare as NFT
            tokenId = rootTokenId(attestation.uid);
            require(rootKeyMap[attestation.uid & TOKEN_ID_MASK].length == 0, "Attestation already exists");
            _mint(attestation.attester, tokenId);
            rootKeyMap[attestation.uid & TOKEN_ID_MASK].push(attestation.uid);
        }
        else //can only be called by root key owner or creator
        {
            tokenId = rootTokenId(attestation.refUID);
            Attestation memory rootAttestation = _eas.getAttestation(attestation.refUID);
            require (attestation.attester == rootAttestation.attester || attestation.attester == ownerOf(tokenId), "Derivative key can only be created by root key owner"); //derivative can be issued by attestation root key or owner of root key NFT
            tokenId += rootKeyMap[attestation.refUID & TOKEN_ID_MASK].length;
            _mint(attestation.recipient, tokenId);
            rootKeyMap[attestation.refUID & TOKEN_ID_MASK].push(attestation.uid);
        }

        //metadata is sourced from website
        return true;
    }

    function getUidForTokenId(uint tokenId) public view returns(bytes32){
        return rootKeyMap[bytes32(tokenId) & TOKEN_ID_MASK][uint(bytes32(tokenId) & (TOKEN_ID_MASK ^ 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))-1];
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
        return CONTRACT_URI;
    }

    /// @notice Returns the metadata for given ID
    /// @param id The ID for which the metadata is to be returned
    /// @return Returns the metadata for given ID

    function tokenURI(uint256 id) public view virtual override returns (string memory) {
        require(_exists(id), "Token does not exist");
        // bytes32 uid = tokenIdUIDMap[id];
        bytes32 uid = getUidForTokenId(id);
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

         return string(abi.encodePacked(BASE_TOKEN_METADATA_URI, block.chainid.toString(), "/", contractAddress(), "?tokenId=", id.toHexString(), 
            "&uid=", uint(getUidForTokenId(id)).toHexString(), "&name=", name, getValidityData(attestation)));
    }

    function getValidityData(Attestation memory attestation) public view returns (string memory) {
        Attestation memory rootAttn = _eas.getAttestation(attestation.refUID);
        uint64 revocationTime = attestation.revocationTime;
        if (rootAttn.revocationTime > 0 && (revocationTime == 0 || revocationTime > rootAttn.revocationTime)) { //Take into account the root key being revoked
            revocationTime = rootAttn.revocationTime;
        }
        return string(abi.encodePacked("&isValid=", getAttestationValidityText(attestation), "&timestamp=", uint256(attestation.time).toString(), 
            "&expirationTime=", uint256(attestation.expirationTime).toString(),
            "&revocationTime=", uint256(revocationTime).toString()));
    }

    function tokenIdToAttestation(uint256 id) public view returns (Attestation memory) {
        require(_exists(id), "Token does not exist");
        return _eas.getAttestation(getUidForTokenId(id));
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

    // no need to nake payable until we add withdraw function
    // function isPayable() public pure virtual override returns (bool) {
    //     return true;
    // }

    function contractAddress() internal view returns (string memory) {
        return Strings.toHexString(uint160(address(this)), 20);
    }

    function validateSignature(bytes32 rootUID, address signer) public view returns (bool result) {
        // Walk the keys for this rootUID and see if any match and haven't been revoked
        //now check derivative keys
        Attestation memory rootAttn = _eas.getAttestation(rootUID); 
        if (!isKeyValid(rootAttn)){
            return false;
        }
        rootUID = rootUID & TOKEN_ID_MASK;
        uint length = rootKeyMap[rootUID].length;
        if (length == 1){
            return verifySigner(rootAttn, signer);
        }
        for (uint256 i = 0; i < rootKeyMap[rootUID].length; i++) {
            bytes32 thisUID = rootKeyMap[rootUID][i];
            Attestation memory thisAttn = _eas.getAttestation(thisUID);  
            if (verifySigner(thisAttn, signer)){
                return true;
            }
        }
        return false;
    }

    function verifySigner(Attestation memory attn, address signer) internal view returns(bool){
        if (signer == getSigningAddressFromAttestation(attn) && isKeyValid(attn)) { //keep checking all keys until true or we run out
            return true;
        }
        return false;
    }

    function isKeyValid(Attestation memory attn) public view returns (bool) {
        //check expiry time and revocation time
        return attn.revocationTime == 0 && (attn.expirationTime == 0 || block.timestamp < attn.expirationTime);
    }

    function getValidSigningAddresses(bytes32 rootUID) public view returns (address[] memory signingKeys, bytes32[] memory uids) {
        uint size = 0;
        rootUID = rootUID & TOKEN_ID_MASK;
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
        bytes32 uid = getUidForTokenId(tokenId);
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
        // code cant be reached
        // _burn(tokenId);
    }

    // Only allow root owner to transfer tokens
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public override(ERC721, IERC721) onlyOwner {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        Attestation memory attestation = _eas.getAttestation(getUidForTokenId(tokenId));
        require(attestation.refUID == bytes32(0), "Only root token can be transferred");
        // TODO attestation.attester is single address, that means tokeken can be only transferred one time from attestor, no way to transfer it again
        require(attestation.attester == msg.sender, "Only original root owner can transfer");
        // TODO test transfer
        _safeTransfer(from, to, tokenId, _data);
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override(ERC721, IERC721) onlyOwner {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        Attestation memory attestation = _eas.getAttestation(getUidForTokenId(tokenId));
        require(attestation.refUID == bytes32(0), "Only root token can be transferred");
        // TODO attestation.attester is single address, that means tokeken can be only transferred one time from attestor, no way to transfer it again
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
        return uint256(uid & TOKEN_ID_MASK) + 1;
    }

}