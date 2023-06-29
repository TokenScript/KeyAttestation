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

struct AttestationRequestData {
    address recipient; // The recipient of the attestation.
    uint64 expirationTime; // The time when the attestation expires (Unix timestamp).
    bool revocable; // Whether the attestation is revocable.
    bytes32 refUID; // The UID of the related attestation.
    bytes data; // Custom attestation data.
    uint256 value; // An explicit ETH amount to send to the resolver. This is important to prevent accidental user errors.
}

/**
 * @dev A struct representing the full arguments of the attestation request.
 */
struct AttestationRequest {
    bytes32 schema; // The unique identifier of the schema.
    AttestationRequestData data; // The arguments of the attestation request.
}

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
    address recipient; // The recipient of the attestation.
    uint64 time; // The time when the attestation is valid from (Unix timestamp).
    uint64 expirationTime; // The time when the attestation expires (Unix timestamp).
    bool revocable; // Whether the attestation is revocable.
    bytes32 refUID; // The UID of the related attestation.
    bytes data; // Custom attestation data.
    uint256 value; // An explicit ETH amount to send to the resolver. This is important to prevent accidental user errors.
    bytes32 schema;
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
        //isValid = true;
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

contract AttestationDecoder is ERC721Enumerable, Ownable, IERC5169, UseKeyAttestation {
    using Strings for uint256;
    using Counters for Counters.Counter;

    uint private _maxSupply = 10000;
    string private _scriptURI;

    string constant EAS_NAME = "EAS Attestation";
    string private constant EIP712_DOMAIN = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";
    bytes32 constant EIP712_DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant ATTEST_TYPEHASH =
        keccak256(
            "Attest(bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data)"
        );

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

    function mintUsingAttestation(bytes memory attestation) public payable returns (uint256) {
        (address issuer, address subjectAddress, uint256 attestationId, bool timeStampValid) = decodeAttestation(attestation);
        require (this.validateKey(issuer) == true, "Attestation not issued by correct authority");
        require (timeStampValid, "Attestion timestamp not valid");
        require (subjectAddress == msg.sender, "Account not authorised to use this Attestation");
        //NB _mint checks for attestation already minted
        _mint(msg.sender, attestationId);

        return attestationId;
    }

    function verifyAttestation(bytes memory attestation) public view returns(bool issuerValid, address subjectAddress, uint256 attestationId, bool timeStampValid) {
        address issuer;
        (issuer, subjectAddress, attestationId, timeStampValid) = decodeAttestation(attestation);
        issuerValid = this.validateKey(issuer);
    }

    function hashTyped(
        AttestationCoreData memory data,
        DecodedDomainData memory domainData
    ) public view returns (bytes32 hash) {
        if (domainData.chainId != block.chainid) {
            revert("Attestation for different chain");
        }

        hash = keccak256(
            abi.encodePacked(
                "\x19\x01", // backslash is needed to escape the character
                keccak256(
                    abi.encode(
                        EIP712_DOMAIN_TYPE_HASH,
                        keccak256(abi.encodePacked(EAS_NAME)),
                        keccak256(abi.encodePacked(domainData.version)),
                        domainData.chainId,
                        domainData.verifyingContract
                    )
                ),
                keccak256(
                    abi.encode(
                        ATTEST_TYPEHASH,
                        data.schema,
                        data.recipient,
                        data.time,
                        data.expirationTime,
                        data.revocable,
                        data.refUID,
                        keccak256(data.data)
                    )
                )
            )
        );
    }

    function recoverEasSigner(
        AttestationCoreData memory data,
        bytes memory signature,
        DecodedDomainData memory domainData
    ) public view returns (address) {
        // EIP721 domain type
        bytes32 hash = hashTyped(data, domainData);

        // split signature
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signature.length != 65) {
            return address(0);
        }
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return address(0);
        } else {
            // verify
            return ecrecover(hash, v, r, s);
        }
    }

    function getRevocationHash(AttestationCoreData memory payloadObjectData) public pure returns (bytes32 revocationHash) {
        // generate Attestation UID
        uint32 nonce = 0;
        bytes memory pack = abi.encodePacked(
            bytesToHex(abi.encodePacked(payloadObjectData.schema)),
            payloadObjectData.recipient,
            address(0),
            payloadObjectData.time,
            payloadObjectData.expirationTime,
            payloadObjectData.revocable,
            payloadObjectData.refUID,
            payloadObjectData.data,
            nonce
        );

        revocationHash = keccak256(pack);
    }

    function mintUsingEasAttestation(AttestationCoreData memory easAttestation, bytes memory signature) public returns (uint256) {
        (bool issuerValid,, address subjectAddress, bool attnValid, uint64 revocationTime) = verifyEASAttestation(easAttestation, signature);
        //(address issuer, address subjectAddress, uint256 attestationId, bool timeStampValid) = decodeAttestation(attestation);
        require (issuerValid == true, "Attestation not issued by correct authority");
        require (revocationTime == 0, "Attestation has been revoked");
        require (attnValid, "Attestion timestamp not valid");
        require (subjectAddress == msg.sender, "Account not authorised to use this Attestation");
        //pull ticketId from the attestation
        (,string memory ticketId,,) = decodeAttestationData(easAttestation);

        //convert ticketId to uint256
        bytes32 ticketHash = keccak256(bytes(ticketId));
        uint256 ticketHashVal = uint256(ticketHash);

        //NB _mint checks for attestation already minted
        _mint(msg.sender, ticketHashVal);

        return ticketHashVal;
    }

    function decodeAttestationData(AttestationCoreData memory easAttestation) public pure returns (string memory eventId, string memory ticketId, uint8 ticketClass, bytes memory commitment) {
        (eventId, ticketId, ticketClass, commitment) = abi.decode(easAttestation.data, (string, string, uint8, bytes));
    }

    function verifyEASAttestation(AttestationCoreData memory easAttestation, bytes memory signature) public view returns(bool issuerValid, address issuer, address subjectAddress, bool attnValid, uint64 revocationTime) {
        DecodedDomainData memory attnDomain = DecodedDomainData("0.26", block.chainid, 0xC2679fBD37d54388Ce493F1DB75320D236e1815e);
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

    function verifyEasRevoked(
        AttestationCoreData memory payloadObjectData,
        address issuer,
        address verifyingContract
    ) internal view returns (RevokeData memory revoke) {
        revoke.uid = getRevocationHash(payloadObjectData);
        IEAS eas = IEAS(verifyingContract);

        revoke.time = eas.getRevokeOffchain(issuer, revoke.uid);
    }

    function bytesToHex(bytes memory buffer) internal pure returns (string memory) {
        // Fixed buffer size for hexadecimal convertion
        bytes memory converted = new bytes(buffer.length * 2);

        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }

    function burnToken(uint256 tokenId) public {
        require(_exists(tokenId), "burn: nonexistent token");
        require(ownerOf(tokenId) == msg.sender || msg.sender == owner(), "Token must be owned");
        _burn(tokenId);
    }

    ///ATTESTATION

    bytes1 constant BOOLEAN_TAG         = bytes1(0x01);
    bytes1 constant INTEGER_TAG         = bytes1(0x02);
    bytes1 constant BIT_STRING_TAG      = bytes1(0x03);
    bytes1 constant OCTET_STRING_TAG    = bytes1(0x04);
    bytes1 constant NULL_TAG            = bytes1(0x05);
    bytes1 constant OBJECT_IDENTIFIER_TAG = bytes1(0x06);
    bytes1 constant EXTERNAL_TAG        = bytes1(0x08);
    bytes1 constant ENUMERATED_TAG      = bytes1(0x0a); // decimal 10
    bytes1 constant SEQUENCE_TAG        = bytes1(0x10); // decimal 16
    bytes1 constant SET_TAG             = bytes1(0x11); // decimal 17
    bytes1 constant SET_OF_TAG          = bytes1(0x11);

    bytes1 constant NUMERIC_STRING_TAG  = bytes1(0x12); // decimal 18
    bytes1 constant PRINTABLE_STRING_TAG = bytes1(0x13); // decimal 19
    bytes1 constant T61_STRING_TAG      = bytes1(0x14); // decimal 20
    bytes1 constant VIDEOTEX_STRING_TAG = bytes1(0x15); // decimal 21
    bytes1 constant IA5_STRING_TAG      = bytes1(0x16); // decimal 22
    bytes1 constant UTC_TIME_TAG        = bytes1(0x17); // decimal 23
    bytes1 constant GENERALIZED_TIME_TAG = bytes1(0x18); // decimal 24
    bytes1 constant GRAPHIC_STRING_TAG  = bytes1(0x19); // decimal 25
    bytes1 constant VISIBLE_STRING_TAG  = bytes1(0x1a); // decimal 26
    bytes1 constant GENERAL_STRING_TAG  = bytes1(0x1b); // decimal 27
    bytes1 constant UNIVERSAL_STRING_TAG = bytes1(0x1c); // decimal 28
    bytes1 constant BMP_STRING_TAG      = bytes1(0x1e); // decimal 30
    bytes1 constant UTF8_STRING_TAG     = bytes1(0x0c); // decimal 12

    bytes1 constant CONSTRUCTED_TAG     = bytes1(0x20); // decimal 28

    bytes1 constant LENGTH_TAG          = bytes1(0x30);
    bytes1 constant VERSION_TAG         = bytes1(0xA0);
    bytes1 constant COMPOUND_TAG        = bytes1(0xA3);

    uint constant TIMESTAMP_GAP = 360; // 6 minutes

    uint256 constant IA5_CODE = uint256(bytes32("IA5")); //tags for disambiguating content
    uint256 constant DEROBJ_CODE = uint256(bytes32("OBJID"));

    bytes constant emptyBytes = new bytes(0x00);

    struct Length {
        uint decodeIndex;
        uint length;
    }

    function decodeAttestation(bytes memory attestation) private view returns(address issuer, address subjectAddress, uint256 attestationId, bool timeStampValid)
    {
        uint256 decodeIndex = 0;
        uint256 length = 0;
        uint256 hashIndex;
        uint256 timeStart;
        uint256 timeFinish;
        bytes memory preHash;
        bytes memory sigData;

        (length, hashIndex, ) = decodeLength(attestation, 0); //131 (total length, primary header)

        (attestationId, subjectAddress, decodeIndex, timeStart, timeFinish) = recoverAttestationData(attestation, hashIndex);

        timeStampValid = block.timestamp > (timeStart - TIMESTAMP_GAP) && block.timestamp < timeFinish;

        preHash = copyDataBlock(attestation, hashIndex, (decodeIndex - hashIndex));

        (length, sigData, ) = decodeElementOffset(attestation, decodeIndex, 1); // Signature

        //perform ecrecover
        issuer = recoverSigner(preHash, sigData);
    }


    //////////////////////////////////////////////////////////////
    // DER Structure Decoding
    //////////////////////////////////////////////////////////////

    function recoverAttestationData(bytes memory attestation, uint256 decodeIndex) public pure returns(uint256 attestationId, address subjectAddress, uint256 newIndex, uint256 startTime, uint256 endTime)
    {
        uint256 length;
        bytes memory data;

        (length, decodeIndex, ) = decodeLength(attestation, decodeIndex);

        newIndex = decodeIndex + length;

        (length, data, decodeIndex, ) = decodeElement(attestation, decodeIndex); // attestationId

        attestationId = bytesToUint(data);

        (length, data, decodeIndex, ) = decodeElement(attestation, decodeIndex); // subject address

        //convert addressValue to address
        subjectAddress = address(uint160(asciiToUintAsm(data)));

        (decodeIndex, startTime, endTime) = decodeTimeBlock(attestation, decodeIndex);
    }

    function getAttestationTimeStamp(bytes memory attestation) public pure returns (uint256 start, uint256 finish, address subjectAddress, uint256 attestationId)
    {
        uint256 decodeIndex = 0;

        (, decodeIndex, ) = decodeLength(attestation, 0); //131 (total length, primary header)

        (attestationId, subjectAddress, decodeIndex, start, finish) = recoverAttestationData(attestation, decodeIndex);
    }

    function checkTimeStamp(bytes memory attestation, uint256 decodeIndex) internal view returns (uint256 index, bool valid)
    {
        bytes memory timeBlock;
        uint256 length;

        (, decodeIndex, ) = decodeLength(attestation, decodeIndex);
        (length, timeBlock, decodeIndex, ) = decodeElement(attestation, decodeIndex);
        uint256 startTime = bytesToUint(timeBlock);
        (, timeBlock, index,) = decodeElement(attestation, decodeIndex);
        uint256 endTime = bytesToUint(timeBlock);
        valid = block.timestamp > (startTime - TIMESTAMP_GAP) && block.timestamp < endTime;
    }

    function decodeTimeBlock(bytes memory attestation, uint256 decodeIndex) internal pure returns (uint256 index, uint256 startTime, uint256 endTime)
    {
        bytes memory timeBlock;
        uint256 length;

        (, decodeIndex, ) = decodeLength(attestation, decodeIndex);
        (length, timeBlock, decodeIndex, ) = decodeElement(attestation, decodeIndex);
        startTime = bytesToUint(timeBlock);
        (, timeBlock, index,) = decodeElement(attestation, decodeIndex);
        endTime = bytesToUint(timeBlock);
    }

    function recoverSigner(bytes memory prehash, bytes memory signature) internal pure returns(address signer)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        return ecrecover(keccak256(prehash), v, r, s);
    }

    function splitSignature(bytes memory sig)
    internal pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {

        // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
        // second 32 bytes
            s := mload(add(sig, 64))
        // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }
    }

    //Truncates if input is greater than 32 bytes; we only handle 32 byte values.
    function bytesToUint(bytes memory b) public pure returns (uint256 conv)
    {
        if (b.length < 0x20) //if b is less than 32 bytes we need to pad to get correct value
        {
            bytes memory b2 = new bytes(32);
            uint startCopy = 0x20 + 0x20 - b.length;
            assembly
            {
                let bcc := add(b, 0x20)
                let bbc := add(b2, startCopy)
                mstore(bbc, mload(bcc))
                conv := mload(add(b2, 32))
            }
        }
        else
        {
            assembly
            {
                conv := mload(add(b, 32))
            }
        }
    }

    //////////////////////////////////////////////////////////////
    // DER Helper functions
    //////////////////////////////////////////////////////////////

    function decodeDERData(bytes memory byteCode, uint dIndex) internal pure returns(bytes memory data, uint256 index, uint256 length, bytes1 tag)
    {
        return decodeDERData(byteCode, dIndex, 0);
    }

    function copyDataBlock(bytes memory byteCode, uint dIndex, uint length) internal pure returns(bytes memory data)
    {
        uint256 blank = 0;
        uint256 index = dIndex;

        uint dStart = 0x20 + index;
        uint cycles = length / 0x20;
        uint requiredAlloc = length;

        if (length % 0x20 > 0) //optimise copying the final part of the bytes - remove the looping
        {
            cycles++;
            requiredAlloc += 0x20; //expand memory to allow end blank
        }

        data = new bytes(requiredAlloc);

        assembly {
            let mc := add(data, 0x20) //offset into bytes we're writing into
            let cycle := 0

            for
            {
                let cc := add(byteCode, dStart)
            } lt(cycle, cycles) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
                cycle := add(cycle, 0x01)
            } {
                mstore(mc, mload(cc))
            }
        }

        //finally blank final bytes and shrink size
        if (length % 0x20 > 0)
        {
            uint offsetStart = 0x20 + length;
            assembly
            {
                let mc := add(data, offsetStart)
                mstore(mc, mload(add(blank, 0x20)))
            //now shrink the memory back
                mstore(data, length)
            }
        }
    }

    function decodeDERData(bytes memory byteCode, uint dIndex, uint offset) internal pure returns(bytes memory data, uint256 index, uint256 length, bytes1 tag)
    {
        index = dIndex;

        (length, index, tag) = decodeLength(byteCode, index);

        if (offset <= length)
        {
            uint requiredLength = length - offset;
            uint dStart = index + offset;

            data = copyDataBlock(byteCode, dStart, requiredLength);
        }
        else
        {
            data = bytes("");
        }

        index += length;
    }

    function decodeElement(bytes memory byteCode, uint decodeIndex) internal pure returns(uint256 length, bytes memory content, uint256 newIndex, bytes1 tag)
    {
        (content, newIndex, length, tag) = decodeDERData(byteCode, decodeIndex);
    }

    function decodeElementOffset(bytes memory byteCode, uint decodeIndex, uint offset) internal pure returns(uint256 length, bytes memory content, uint256 newIndex)
    {
        (content, newIndex, length, ) = decodeDERData(byteCode, decodeIndex, offset);
    }

    function stringToUint(string memory s) public pure returns (uint) {
        bytes memory b = bytes(s);
        uint result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
        return result;
    }

    function decodeLength(bytes memory byteCode, uint decodeIndex) internal pure returns(uint256 length, uint256 newIndex, bytes1 tag)
    {
        uint codeLength = 1;
        length = 0;
        newIndex = decodeIndex;
        tag = bytes1(byteCode[newIndex++]);

        if ((byteCode[newIndex] & 0x80) == 0x80)
        {
            codeLength = uint8((byteCode[newIndex++] & 0x7f));
        }

        for (uint i = 0; i < codeLength; i++)
        {
            length |= uint(uint8(byteCode[newIndex++] & 0xFF)) << ((codeLength - i - 1) * 8);
        }
    }

    // Optimised hex ascii to uint conversion (eg 0x30373038 is 0x0708)
    function asciiToUintAsm(bytes memory asciiData) public pure returns(uint256 asciiValue)
    {
        bytes memory hexData = new bytes(32);
        bytes1 b1;
        bytes1 b2;
        bytes1 sum;

        assembly {
            let index := 0        // current write index, we have to count upwards to avoid an unsigned 0xFFFFFF infinite loop ..
            let topIndex := 0x27  // final ascii to read
            let bIndex := 0x20    // write index into bytes array we're using to build the converted number

            for
            {
                let cc := add(asciiData, topIndex) // start reading position in the ascii data
            } lt(index, topIndex) {
                index := add(index, 0x02) // each value to write is two bytes
                cc := sub(cc, 0x02)
                bIndex := sub(bIndex, 0x01) // index into scratch buffer
            } {
                //build top nibble of value
                b1 := and(mload(cc), 0xFF)
                if gt(b1, 0x39) { b1 := sub(b1, 0x07) } //correct for ascii numeric value
                b1 := sub(b1, 0x30)
                b1 := mul(b1, 0x10) //move to top nibble

                //build bottom nibble
                b2 := and(mload(add(cc, 0x01)), 0xFF)
                if gt(b2, 0x39) { b2 := sub(b2, 0x07) } //correct for ascii numeric value
                b2 := sub(b2, 0x30)

                //combine both nibbles
                sum := add(b1, b2)

                //write the combined byte into the scratch buffer
                // - note we have to point 32 bytes ahead as 'sum' uint8 value is at the end of a 32 byte register
                let hexPtr := add(hexData, bIndex)
                mstore(hexPtr, sum)
            }

            mstore(hexData, 0x20)   // patch the variable size info we corrupted in the mstore
                                    // NB: we may not need to do this, we're only using this buffer as a memory scratch
                                    // However EVM stack cleanup unwind may break, TODO: determine if it's safe to remove
            asciiValue := mload(add(hexData, 32)) // convert to uint
        }
    }
}