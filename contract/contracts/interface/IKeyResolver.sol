// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

// import { ISchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/ISchemaResolver.sol";

interface IKeyResolver {
    function validateSignature(bytes32 rootUID, address signer) external view returns (bool isValid); 
}