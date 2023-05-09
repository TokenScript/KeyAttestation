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

    const debugAttestorKey = '0x5f7bFe752Ac1a45F67497d9dCDD9BbDA50A83955';
    const debugIssuerKey = '0xbf9Ae773d7D724b9632564fbE2c782Cc2Ed8817c';
    const testNetAttestorKey = '0x538080305560986811c3c1A2c5BCb4F37670EF7e';
    const testNetIssuerKey = '0xD5905B36657Dd05a2EF4562267c59A36497A5268';
    const currentVerifyAttestationAddr = '0xfEA88F5f78b7c74E969DE5c79De50452C509a076';
    const currentRoyaltyReceiverAddr = '0xD11814D41B21BfA7f90182F7EE0d0029dd0cF8aa';

    const carlaReceiveAddress = '0xae623F8226Ff39Fd2AC5D79EbfE00995FD22a63b';
    const charity1ReceiveAddress = '0x5E11F2DF9843a6e23A8E491c330437EED529cAd7';
    const charity2ReceiveAddress = '0x28E5d3b9d5004c9CE21EDfCB91447314F25265C1';

    let proxyAddr = '0x28d5B2E6f30A9b54DCBE8792543fB0232F4f3658';

    const LPNFT = await ethers.getContractFactory("LaPrairieNFTProduction");
    //proxyLPNFT = await upgrades.deployProxy(LPNFT.connect(mainDeployKey), [currentRoyaltyReceiverAddr] ,{ kind: 'uups' });
    //await proxyLPNFT.deployed();

    //console.log("LP NFT Addr: " + proxyLPNFT.address);
    
    console.log("LP NFT Addr: " + proxyAddr);
    console.log("Owner: " + mainDeployKey.address);

    console.log("Verify Addr: " + currentVerifyAttestationAddr);
    console.log("RoyalyReceiver Addr: " + currentRoyaltyReceiverAddr);

    console.log('User balance: ', ethers.utils.formatEther(await ethers.provider.getBalance(mainDeployKey.address)), "\n");

    //Call init on logic address to fix "Exploding Kittens" exploit
    //now call init on the logic contract
    const currentProxyLogicAddress = await getImplementationAddress(ethers.provider, proxyAddr);
    
    console.log("[LOGIC CONTRACTS] --> logic address for LP NFT: " + currentProxyLogicAddress);
    let logicLPNFT = LPNFT.attach(currentProxyLogicAddress);
    await logicLPNFT.initialize(currentRoyaltyReceiverAddr);
    console.log("[LOGIC CONTRACTS] --> initialize logic for LPNFT to prevent exploding kittens");

    console.log('User balance: ', ethers.utils.formatEther(await ethers.provider.getBalance(mainDeployKey.address)), "\n");

})();

// npx hardhat run scripts/deploy-prod.js --network mumbai