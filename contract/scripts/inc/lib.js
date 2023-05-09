const { ethers } = require("hardhat");
require("dotenv").config();
const { PRIVATE_KEY_MAIN, PRIVATE_KEY_RETORT, PRIVATE_KEY_MY_NFT, PRIVATE_KEY_REMIX } = process.env;

const env_keys_required = [
    "PRIVATE_KEY_MAIN",
    "PRIVATE_KEY_RETORT",
    "PRIVATE_KEY_MY_NFT",
    "PRIVATE_KEY_REMIX"
];

function calcContractAddress(sender, nonce)
{
    const rlp = require('rlp');
    const keccak = require('keccak');

    var input_arr = [ sender.address, nonce ];
    var rlp_encoded = rlp.encode(input_arr);

    var contract_address_long = keccak('keccak256').update(rlp_encoded).digest('hex');

    var contract_address = contract_address_long.substring(24); //Trim the first 24 characters.
    return "0x" + contract_address;
}

function requiredEnvKeysExists(){
    let $checkOk = true;

    env_keys_required.forEach((item) => {
        try {
            if (!eval(item)) throw new Error(`"${item}" not configured. check your .env file`)
        } catch (e) {
            console.error(e.message);
            $checkOk = false;
        }
    })
    return $checkOk;
}

function ethersDebugMessages(message, e){
    console.error(message);
    console.error('Reason : ' + e.reason);
    console.error('Code   : ' + e.code);
    console.error('Method : ' + e.method);
    console.error('Error  : ' + e.error);
}

async function createWalletsAndAddresses(provider){

    // check if all required keys exist in the ethereum/.env file
    if (!requiredEnvKeysExists()) return;

    const [owner] = await ethers.getSigners();

    const mainDeployKey = new ethers.Wallet(PRIVATE_KEY_MAIN, provider);
    const retortDeployKey = new ethers.Wallet(PRIVATE_KEY_RETORT, provider); // retort deployment key
    const myNFTDeployKey = new ethers.Wallet(PRIVATE_KEY_MY_NFT, provider);  // MyNFT mintable deployment key
    const remixDeployKey = new ethers.Wallet(PRIVATE_KEY_REMIX, provider);

    console.log( 'mainDeployKey address ' , mainDeployKey.address);
    console.log( 'retortDeployKey address ' , retortDeployKey.address);
    console.log( 'myNFTDeployKey address ' , myNFTDeployKey.address);
    console.log( 'RemixDeployKey address ' , remixDeployKey.address);

    const { chainId } = await ethers.provider.getNetwork()

    console.log( 'Chain Id: ' , chainId);

    if (chainId == 31337 || chainId == 1337) { //default HH ganache Id for testing, provide balances
        await owner.sendTransaction({
            to: mainDeployKey.address,
            value: ethers.utils.parseEther("3.0")
        });

        await owner.sendTransaction({
            to: retortDeployKey.address,
            value: ethers.utils.parseEther("3.0")
        });

        await owner.sendTransaction({
            to: myNFTDeployKey.address,
            value: ethers.utils.parseEther("3.0")
        });

        await owner.sendTransaction({
            to: remixDeployKey.address,
            value: ethers.utils.parseEther("3.0")
        });
    }

    let startBalance2 = await ethers.provider.getBalance(retortDeployKey.address);
    console.log( 'RetortDeployKey balance ' , ethers.utils.formatEther(startBalance2));

    startBalance2 = await ethers.provider.getBalance(mainDeployKey.address);
    console.log( 'mainDeployKey balance ' , ethers.utils.formatEther(startBalance2));

    startBalance2 = await ethers.provider.getBalance(myNFTDeployKey.address);
    console.log( 'myNFTDeployKey balance ' , ethers.utils.formatEther(startBalance2));

    startBalance2 = await ethers.provider.getBalance(remixDeployKey.address);
    console.log( 'RemixDeployKey balance ' , ethers.utils.formatEther(startBalance2));

    //calculate addresses
    const DvPAddress = calcContractAddress(mainDeployKey, 0x00);
    const verifyAttestationAddress = calcContractAddress(mainDeployKey, 0x01);
    const RetortProxyAddress = calcContractAddress(retortDeployKey, 0x01);
    const RemixProxyAddress = calcContractAddress(remixDeployKey, 0x01);
    const MyNFTProxyAddress = calcContractAddress(myNFTDeployKey, 0x01);

    return {
        mainDeployKey,
        retortDeployKey,
        myNFTDeployKey,
        remixDeployKey,
        DvPAddress,
        verifyAttestationAddress,
        RetortProxyAddress,
        RemixProxyAddress,
        MyNFTProxyAddress
    }

}

module.exports = {
    createWalletsAndAddresses, ethersDebugMessages
}
