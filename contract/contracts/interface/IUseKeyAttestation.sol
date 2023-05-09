// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

interface IUseKeyAttestation {
    function updateKeyUID(bytes32 keyUID) external;
    function validateKey(address attestationSigningAddress) external returns (bool isValid);
}