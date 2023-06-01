// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import { ERC5169 } from "stl-contracts/ERC/ERC5169.sol";
import { UseKeyAttestation } from "../UseKeyAttestation.sol";
import { ASNAttestationDecoder } from "../ASNAttestation/ASNAttestationDecoder.sol";

// just to esimate gas usage difference
contract TestErc721 is ERC721 {
    constructor() ERC721("", "") {}

    function mint() external {
        _mint(msg.sender,1);
    }
}

// TODO should be Enumerable
contract DoorAttestation is ERC721, Ownable, ERC5169, UseKeyAttestation, ASNAttestationDecoder {
    using Strings for uint256;
    using Counters for Counters.Counter;

    // unused
    // uint private _maxSupply = 10000;

    constructor(bytes32 uid, address resolverAddress) ERC721("Door Attestation", "DATT") UseKeyAttestation(uid, resolverAddress) {}

    function contractURI() public pure returns (string memory) {
        return "ipfs://QmUUFFGVRKeW5dGMVTsTowuucDPxv5EadVsAoNT3cF5Ra1";
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "tokenURI: URI query for nonexistent token");
        return "ipfs://QmUe2QBZctMmi7adQF5QPWKyNjxgLcgHieBx6ujmzPw4BZ";
    }

    function updateKeyUID(bytes32 keyUID) public onlyOwner {
        _updateKeyUID(keyUID);
    }

    // no-payable, because we dont have withdraw code
    function mintUsingAttestation(bytes memory attestation) public returns (uint256) {
        (address issuer, address subjectAddress, uint256 attestationId, bool timeStampValid) = verifyAttestation(attestation);
        //require (issuer == _issuerAddress, "Attestation not issued by correct authority");
        require (timeStampValid, "Attestion timestamp not valid");
        require (subjectAddress == msg.sender, "Account not authorised to use this Attestation");
        bool keyValid = this.validateKey(issuer);
        require (keyValid, "Attestation issuer key not valid");

        //NB _mint checks for attestation already minted
        _mint(msg.sender, attestationId);

        return attestationId;
    }

    function validateAttestation(bytes memory attestation) public view returns (bool isValid)
    {
        (address issuer,,, bool timeStampValid) = verifyAttestation(attestation);
        bool keyValid = this.validateKey(issuer);
        isValid = keyValid && timeStampValid;
    }

    function burnToken(uint256 tokenId) public {
        require(_exists(tokenId), "burn: nonexistent token");
        require(ownerOf(tokenId) == msg.sender || msg.sender == owner(), "Token must be owned");
        _burn(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, ERC5169) returns (bool) {
        return
            ERC5169.supportsInterface(interfaceId) ||
            super.supportsInterface(interfaceId);
    }

    function _authorizeSetScripts(string[] memory newScriptURI) internal override {

    }
}
