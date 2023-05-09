const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');
const { getImplementationAddress } = require('@openzeppelin/upgrades-core');

(async ()=>{
    const {
        mainDeployKey
    } = await createWalletsAndAddresses(ethers.provider);

    const debugAttestorKey = '0x5f7bFe752Ac1a45F67497d9dCDD9BbDA50A83955';
    const debugIssuerKey = '0xbf9Ae773d7D724b9632564fbE2c782Cc2Ed8817c';
    const testNetAttestorKey = '0x538080305560986811c3c1A2c5BCb4F37670EF7e';
    const testNetIssuerKey = '0xD5905B36657Dd05a2EF4562267c59A36497A5268';
    const currentVerifyAttestationAddr = '0x918a754ecefC27F243fbBBd4b93bB6C38a636371';
    const currentRoyaltyReceiverAddr = '0x4351eE5DE14d824623219e315C1381399f8D494B';
    const carlaReceiveAddress = '0xae623F8226Ff39Fd2AC5D79EbfE00995FD22a63b';
    const charity1ReceiveAddress = '0x5E11F2DF9843a6e23A8E491c330437EED529cAd7';
    const charity2ReceiveAddress = '0x28E5d3b9d5004c9CE21EDfCB91447314F25265C1';

    const currentNFTProxyAddress = '0x73E51E191090c117526B446dFdA259c1473c5f66'; //On Rinkeby

    const LPNFT = await ethers.getContractFactory("LaPrairieNFTTestNet");
    let proxyLPNFT = LPNFT.attach(currentNFTProxyAddress);
    let ownerAddress = await proxyLPNFT.owner();

    if (ownerAddress.toLowerCase() !== mainDeployKey.address.toLowerCase()) {
        console.log(`deployKey doesnt equal to the contract.owner(): (${ownerAddress} vs ${mainDeployKey.address}), execution stopping...`);
        return;
    }

    try {
		await proxyLPNFT.connect(mainDeployKey).setRoyaltyContract(currentRoyaltyReceiverAddr);

        console.log('[PROXY & LOGIC CONTRACTS] --> LaPrairieNFTTestNet RoyaltyReceiver Contract updated to ', currentRoyaltyReceiverAddr);
    } catch (e) {
        ethersDebugMessages('LaPrairieNFTTestNet upgrade FAILED', e)
    }

    console.log('LaPrairieNFTTestNet Deploy Key balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(mainDeployKey.address)), "\n");
})();
// npx hardhat run scripts/update-rr-address.js --network rinkeby