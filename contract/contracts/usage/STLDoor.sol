// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaRecord, ISchemaRegistry } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import { Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { IEAS, EAS } from "@ethereum-attestation-service/eas-contracts/contracts/EAS.sol";
import { EASverify } from "stl-contracts/attestation/EASverify.sol";

interface IKeyResolver is ISchemaResolver {
    function validateSignature(bytes32 rootUID, address signer) external view returns (bool isValid); 
}

interface IUseKeyAttestation {
    function updateKeyUID(bytes32 keyUID) external;
    function validateKey(address attestationSigningAddress) external returns (bool isValid);
}

struct DecodedDomainData {
    string version;
    uint256 chainId;
    address verifyingContract;
}

struct AttestationCoreData {
    bytes32 schema; // The UID of the associated EAS schema
    address recipient; // The recipient of the attestation.
    uint64 time; // The time when the attestation is valid from (Unix timestamp).
    uint64 expirationTime; // The time when the attestation expires (Unix timestamp).
    bool revocable; // Whether the attestation is revocable.
    bytes32 refUID; // The UID of the related attestation.
    bytes data; // The actual Schema data (eg eventId: 12345, ticketId: 6 etc)
}

struct RevokeData {
    bytes32 uid;
    uint64 time;
}

abstract contract UseKeyAttestation is IUseKeyAttestation {
    address immutable EAS_ADDRESS;
    bytes32 keyUID;
    IKeyResolver keyResolver;

    constructor(bytes32 _keyUID, address _easAddress) {
        EAS_ADDRESS = _easAddress;
        _updateKeyUID(_keyUID);
    }

    function _updateKeyUID(bytes32 _keyUID) internal {
        keyUID = _keyUID;

        IEAS easResolver = IEAS(EAS_ADDRESS);
        //get schema UID
        bytes32 schema = easResolver.getAttestation(_keyUID).schema;

        //get standard schema resolver
        ISchemaRegistry schemaRegistry = ISchemaRegistry(easResolver.getSchemaRegistry());
        //get schema for the attestation
        SchemaRecord memory thisSchema = schemaRegistry.getSchema(schema);
        keyResolver = IKeyResolver(address(thisSchema.resolver));
    }

    //TODO: fine grained attestation failure (key expired, wrong key, key revoked)
    function validateKey(address attestationSigningAddress) external view returns (bool isValid) {

        //validate attestation
        isValid = keyResolver.validateSignature(keyUID, attestationSigningAddress);
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

contract AttestationDecoder is ERC721Enumerable, Ownable, IERC5169, UseKeyAttestation, EASverify {
    using Strings for uint256;

    string private _scriptURI;

    string private constant EIP712_DOMAIN = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";

    bytes32 private constant TOKEN_ID_MASK = 0x0000000000000000000000000000000000000000000000000000FFFFFFFFFFFF;

    address private easContractAddress;

    //0xee99de42f544fa9a47caaf8d4a4426c1104b6d7a9df7f661f892730f1b5b1e23
    //0xC2679fBD37d54388Ce493F1DB75320D236e1815e
    constructor(bytes32 keyUID, address _easContractAddress) ERC721("Test Attestation Tokens", "TATT") UseKeyAttestation(keyUID, _easContractAddress) {
        _scriptURI = "";
        easContractAddress = _easContractAddress;
    }

    function getChainId() public view returns (uint256 chainId) {
        chainId = block.chainid;
    }

    function updateKeyUID(bytes32 keyUID) public onlyOwner {
        _updateKeyUID(keyUID);
    }

    function contractURI() public pure returns (string memory) {
        return "ipfs://QmUUFFGVRKeW5dGMVTsTowuucDPxv5EadVsAoNT3cF5Ra1";
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "tokenURI: URI query for nonexistent token");
        return "ipfs://QmUe2QBZctMmi7adQF5QPWKyNjxgLcgHieBx6ujmzPw4BZ";
    }

    function scriptURI() public view override returns (string memory) {
        return _scriptURI;
    }

    function updateScriptURI(string memory newScriptURI) public override onlyOwner {
        _scriptURI = newScriptURI;
        emit ScriptUpdate(newScriptURI);
    }

    function mintUsingEasAttestation(AttestationCoreData memory easAttestation, bytes memory signature) public returns (uint256) {
        (bool issuerValid,, address subjectAddress, bool attnValid, uint64 revocationTime) = verifyEASAttestation(easAttestation, signature);
        require (issuerValid == true, "Attestation not issued by correct authority");
        require (revocationTime == 0, "Attestation has been revoked");
        require (attnValid, "Attestion timestamp not valid");
        require (subjectAddress == msg.sender, "Account not authorised to use this Attestation");
        uint256 tokenId = calculateTokenId(easAttestation);

        //NB _mint checks for attestation already minted
        _mint(msg.sender, tokenId);

        return tokenId;
    }

    function calculateTokenId(AttestationCoreData memory easAttestation) public pure returns (uint256) {
        (string memory eventId,string memory ticketId,,) = decodeAttestationData(easAttestation);
        //convert ticketId to uint256
        bytes32 ticketHash = keccak256(abi.encodePacked(bytes(eventId), bytes(ticketId)));
        //mask the bottom 10 bytes
        return uint256(ticketHash & TOKEN_ID_MASK); //reduce to bottom 6 bytes
    }

    function isRedeemed(AttestationCoreData memory easAttestation) public view returns (bool) {
        uint256 tokenId = calculateTokenId(easAttestation);
        return _exists(tokenId);
    }

    function verifyEASAttestation(AttestationCoreData memory easAttestation, bytes memory signature) 
            public view returns(bool issuerValid, address issuer, address subjectAddress, bool attnValid, uint64 revocationTime) {
        DecodedDomainData memory attnDomain = DecodedDomainData("0.26", block.chainid, 0xC2679fBD37d54388Ce493F1DB75320D236e1815e); //NB: this should be easContractAddress but the attestation was formed for sepolia
        //get hash
        issuer = recoverEasSigner(easAttestation, signature, attnDomain);
        subjectAddress = easAttestation.recipient;

        //check validity of key via library
        issuerValid = this.validateKey(issuer);

        //now check the timestamp
        (attnValid, revocationTime) = isAttnValid(easAttestation, issuer);
    }

    function isAttnValid(AttestationCoreData memory attn, address issuer) public view returns (bool isValid, uint64 revocationTime) {
        //load and check revocation
        isValid = block.timestamp > attn.time && (attn.expirationTime == 0 || block.timestamp < attn.expirationTime);

        if (attn.revocable && isValid) {
            RevokeData memory revokeData = verifyEasRevoked(attn, issuer, easContractAddress);
            isValid = (revokeData.time == 0);
            revocationTime = revokeData.time;
        }
    }

    function burnToken(uint256 tokenId) public {
        require(_exists(tokenId), "burn: nonexistent token");
        require(ownerOf(tokenId) == msg.sender || msg.sender == owner(), "Token must be owned");
        _burn(tokenId);
    }

}