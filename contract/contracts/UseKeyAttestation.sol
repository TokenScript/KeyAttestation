// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";
import { SchemaRecord, ISchemaRegistry } from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import { Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { IEAS, EAS } from "@ethereum-attestation-service/eas-contracts/contracts/EAS.sol";
import "./interface/IUseKeyAttestation.sol";

interface IKeyResolver is ISchemaResolver {
    function validateSignature(bytes32 rootUID, address signer) external view returns (bool isValid); 
}

abstract contract UseKeyAttestation is IUseKeyAttestation {
    address _resolver;
    bytes32 _keyUID;
    IKeyResolver _keyResolver;

    constructor(bytes32 keyUID, address resolverAddress) {
        _resolver = resolverAddress;
        _updateKeyUID(keyUID);
    }

    function _updateKeyUID(bytes32 keyUID) internal {
        _keyUID = keyUID;

        IEAS easResolver = IEAS(_resolver);
        //get schema UID
        bytes32 schema = easResolver.getAttestation(keyUID).schema;

        //get standard schema resolver
        ISchemaRegistry schemaRegistry = ISchemaRegistry(easResolver.getSchemaRegistry());
        //get schema for the attestation
        SchemaRecord memory thisSchema = schemaRegistry.getSchema(schema);
        _keyResolver = IKeyResolver(address(thisSchema.resolver));
    }

    //TODO: fine grained attestation failure (key expired, wrong key, key revoked)
    function validateKey(address attestationSigningAddress) external view returns (bool isValid) {

        //validate attestation
        isValid = _keyResolver.validateSignature(_keyUID, attestationSigningAddress);
    }
}