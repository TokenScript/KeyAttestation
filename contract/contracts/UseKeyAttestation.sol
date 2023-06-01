// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaRecord, ISchemaRegistry } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import { Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { IEAS, EAS } from "@ethereum-attestation-service/eas-contracts/contracts/EAS.sol";
import "./interface/IUseKeyAttestation.sol";
import "./interface/IKeyResolver.sol";

abstract contract UseKeyAttestation is IUseKeyAttestation {
    address immutable EAS_ADDRESS;
    bytes32 keyUID;
    IKeyResolver keyResolver;

    constructor(bytes32 _keyUID, address _easAddress) {
        EAS_ADDRESS = _easAddress;
        _updateKeyUID(_keyUID);
    }

    // TODO do we need to be able to update _easAddress? do we suppose it will stay static
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