const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');
const { getImplementationAddress } = require('@openzeppelin/upgrades-core');

function calcContractAddress(senderAddress, nonce)
{
    const rlp = require('rlp');
    const keccak = require('keccak');

    var input_arr = [ senderAddress, nonce ];
    var rlp_encoded = rlp.encode(input_arr);

    var contract_address_long = keccak('keccak256').update(rlp_encoded).digest('hex');

    var contract_address = contract_address_long.substring(24); //Trim the first 24 characters.
    return "0x" + contract_address;
}

(async ()=>{
    const {
        mainDeployKey
    } = await createWalletsAndAddresses(ethers.provider);

    console.log("Deploy key: " + mainDeployKey.address);

    const { chainId } = await ethers.provider.getNetwork();

    const carlaReceiveAddress = '0xae623F8226Ff39Fd2AC5D79EbfE00995FD22a63b';
    const charity1ReceiveAddress = '0x5E11F2DF9843a6e23A8E491c330437EED529cAd7'; //NOM
    const charity2ReceiveAddress = '0x28E5d3b9d5004c9CE21EDfCB91447314F25265C1'; //ETH

    try {
        //Deploy VerifyAttestation contract
        const VerifyAttestation = await ethers.getContractFactory("VerifyAttestation");
        verifyAttestation = await VerifyAttestation.connect(mainDeployKey).deploy();
        await verifyAttestation.deployed();
    } catch (e) {
        ethersDebugMessages('Verify Attestation Contract Deploy Fail', e);
        return;
    }

    console.log('[LOGIC CONTRACTS] --> Deployed VerifyAttestation');
    console.log('VerifyAttestation address: ' + verifyAttestation.address);
    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(mainDeployKey.address)), "\n");

    try {
        //deploy royalty receiver
        const RoyaltyReceiver = await ethers.getContractFactory("RoyaltyReceiver");
        royaltyReceiver = await RoyaltyReceiver.connect(mainDeployKey).deploy(carlaReceiveAddress, charity2ReceiveAddress);
        await royaltyReceiver.deployed();
    } catch (e) {
        ethersDebugMessages('Royalty Receiver Contract Deploy Fail', e);
        return;
    }

    console.log('[LOGIC CONTRACTS] --> Deployed RoyaltyReceiver');
    console.log('RoyaltyReceiver address: ' + royaltyReceiver.address);
    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(mainDeployKey.address)), "\n");

    console.log('Now update the VerifyContract and RoyaltyReceiver in the LPNFT solidity contract');

})();

// npx hardhat run scripts/deploy-verify-rr.js --network mumbai