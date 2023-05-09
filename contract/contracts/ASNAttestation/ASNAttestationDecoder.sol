// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

abstract contract ASNAttestationDecoder {
    ///ATTESTATION

    function getTime() public view returns (uint time) {
        time = block.timestamp;
    }

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

    function verifyAttestation(bytes memory attestation) public view returns(address issuer, address subjectAddress, uint256 attestationId, bool timeStampValid)
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