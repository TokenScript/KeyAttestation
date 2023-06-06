import {parseEthers} from "../EthUtils";
const { ethers, upgrades } = require('hardhat');
const { getImplementationAddress } = require('@openzeppelin/upgrades-core');
import { ContractTransaction, Event, utils } from 'ethers';

import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import {BigNumber, Contract} from "ethers";
import exp from "constants";

const { solidityKeccak256, hexlify, toUtf8Bytes } = utils;

let abiCoder = new ethers.utils.AbiCoder();
const asn1key = '0x308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004ea4f8d88bf9738928426055abeaa127743f5512b580a59734326926592e15da057a42a40d8c6be657622d927df84988afbd4597aa98c56fe05f7d6afa38319d0';

describe("KeyResolver.deploy", function () {
    let schemaRegistry: Contract;
    let EASContract: Contract;
    let keyResolver: Contract;
    let NFTWithAttestation: Contract;
    let TestNft: Contract;
    let keySchemaUID: string;
    let rootKey1UID: string;
    let rootKey2UID: string;

    let derivedKey1_1UID: string;
    let derivedKey2_1UID: string;
    
    let owner: SignerWithAddress;
    let addr1: SignerWithAddress;
    let addr2: SignerWithAddress;
    let testAddr: SignerWithAddress;
    let testAddr2: SignerWithAddress;
    let deployAddr: SignerWithAddress;
    let nftUserAddr: SignerWithAddress;
    let provider: any;

    const ganacheChainId = 31337;
    const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

    const signedAttestation = '0x308182303c0201390c2841324344334137383045413345394446363346453630453342394546304337323046414641373432300d0204643d0c8c020500858c328c034200d6a9b48c2185d5d5325911666067bf9df835a9feadf1354d6742ca3ac71cb3400ccf07e35dde9d3a2048e7995e2d772f4b5b467bc9eec133ddd63206f6a5d2c81b';
    const signedAttestation58 = '0x308182303c02013a0c2841324344334137383045413345394446363346453630453342394546304337323046414641373432300d0204643d0c8c020500858c328c034200c4952e307bda5c651b6b4b16af054716f600b0ee767a8c1d2d229575ff173d9025dc9b3d81e97484948350e9ac3e064c9983a7ac78e9d4b48781ddf8455286c41b';
    const signedAttestation59 = '0x308182303c02013b0c2841324344334137383045413345394446363346453630453342394546304337323046414641373432300d0204643d0c8c020500858c328c0342009960535b9314b9f263b454f6e4e690c89d13bea513d5ecaf963c7648968852ed1f964c561d84e456ef94f657502f9ec141264601c543704689260fc22bef496f1b';
    const signedAttestation60 = '0x308182303c02013c0c2841324344334137383045413345394446363346453630453342394546304337323046414641373432300d0204643d0c8c020500858c328c034200cfc7317b05bca9744315f26fd0b2f300f406a47f124d6a8c9fca39095f4e2c1d247e8e84d965087c2df5d00fd467651fb49c4e501613a80a235e84c3f2dd848a1b';

     // Fake: Identifier has a different ID number, but correct signature (Twitter imposter)
    const fakeUniversalIdAttestation = '0x3082026a30820217308201c4a003020113020101300906072a8648ce3d040230193117301506035504030c0e6174746573746174696f6e2e69643022180f32303231303932363031333732375a180f39393939313233313132353935395a30393137303506092b06010401817a01390c2868747470733a2f2f747769747465722e636f6d2f7a68616e67776569777520323035353231363737308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300906072a8648ce3d040203420066dd0460a8920709cabc1003c934d5fdfed47af4dd03b51dbaed878093152c9a4335f1eafdc7f2d20fe8dd15dcd08df8a9cc1ca76526a0e2450d80c233cbf36b1c300906072a8648ce3d04020342004ce8adbd9a9a338cd941d8838b68fbea154e02471cfe92a3a0c5559c104275be16841e4fdecff47707b9904866f78ef0d2786d51c7f3894fbbbf7c77b346cb6c1c';
    const attestationSubjectPrivateKey = '0x3C19FF5D453C7891EDB92FE70662D5E45AEF658E9F38DF9B0483F6AE2D8DE66E';
    const anyPrivateKey  = '0x2222222222222222222222222222222222222222222222222222222222222222';
    const anyPrivateKey2 = '0x2222222222222222222222222222222222222222222222222222222222222666';
    const testPrivateKey = '0x2222222222222222222222212345622222222222222222222222222222222666'; //There's no value on this guy :) ID 57 : 0xA2Cd3a780ea3E9DF63Fe60E3b9eF0C720fAfa742

    function calcContractAddress(sender: SignerWithAddress, nonce: number)
    {
        const rlp = require('rlp');
        const keccak = require('keccak');

        var input_arr = [ sender.address, nonce ];
        var rlp_encoded = rlp.encode(input_arr);

        var contract_address_long = keccak('keccak256').update(rlp_encoded).digest('hex');

        var contract_address = contract_address_long.substring(24); //Trim the first 24 characters.
        return "0x" + contract_address;
    }

    const getSchemaUID = (schema: string, resolverAddress: string, revocable: boolean) =>
        solidityKeccak256(['string', 'address', 'bool'], [schema, resolverAddress, revocable]);

    const getUIDsFromAttestEvents = (events?: Event[]): string[] => {
        if (!events) {
          return [];
        }
      
        const attestedEvents = events.filter((e) => e.event === 'Attested');
        if (attestedEvents.length === 0) {
          throw new Error('Unable to process attestation events');
        }
      
        return attestedEvents.map((event) => event.args?.uid);
      };

    const getUIDFromAttestTx = async (res: Promise<ContractTransaction> | ContractTransaction): Promise<string> => {
        const receipt = await (await res).wait();
        return (await getUIDsFromAttestEvents(receipt.events))[0];
    };


    it("deploy contracts", async function(){
        [owner, addr1, addr2] = await ethers.getSigners();

        testAddr = new ethers.Wallet(anyPrivateKey, owner.provider);
        testAddr2 = new ethers.Wallet(attestationSubjectPrivateKey, owner.provider); //testAddr2 address is subjectAddress
        deployAddr = new ethers.Wallet(anyPrivateKey2, owner.provider);
        nftUserAddr = new ethers.Wallet(testPrivateKey, owner.provider);

        await addr1.sendTransaction({
            to: deployAddr.address,
            value: ethers.utils.parseEther("1.0")
        });

        await addr1.sendTransaction({
            to: nftUserAddr.address,
            value: ethers.utils.parseEther("1.0")
        });

        provider = owner.provider;

        console.log("Deploy Address: " + deployAddr.address);

        //Deploy SchemaResolver
        const SchemaRegistry = await ethers.getContractFactory("SchemaRegistry");
        schemaRegistry = await SchemaRegistry.connect(deployAddr).deploy();
        await schemaRegistry.deployed();
        console.log("SchemaRegistry Addr: " + schemaRegistry.address);

        //Now Deploy EAS - need the address of SchemaRegistry
        const EAS = await ethers.getContractFactory("EAS");
        EASContract = await EAS.connect(deployAddr).deploy(schemaRegistry.address);

        console.log("EAS Addr: " + EASContract.address);

        //Now deploy the KeyResolver contract
        const KeyResolver = await ethers.getContractFactory("KeyResolver");
        keyResolver = await KeyResolver.connect(deployAddr).deploy(EASContract.address);

        console.log("Key Resolver Addr: " + keyResolver.address);

        //register our schema : register(string schema,address resolver,bool revocable)
        const schema = "string KeyDecription,bytes ASN1Key,bytes PublicKey";
        const resolver = keyResolver.address;
        const revocable = true;

        // TODO test saved schema vs generated
        await schemaRegistry.connect(deployAddr).register(schema, resolver, revocable);

        keySchemaUID = getSchemaUID(schema, resolver, revocable);

        console.log("Key Schema UID: " + keySchemaUID);
    });

    it("Push rootkeys", async function(){
        {
            console.log("Create root key #1");

            let expirationTime: number;
            let revocable: boolean;
            let refUID: string;
            let data: any;
            //let rootKeyData: any;
            //let derivedKeyData: any;
            
            expirationTime = 0;
            revocable = true;
            refUID = ZERO_BYTES32;

            data = (abiCoder.encode(['string','bytes','bytes'],['RootKey1',asn1key,'0x950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd']));

            rootKey1UID = await getUIDFromAttestTx(
                EASContract.attest({
                  schema: keySchemaUID,
                  data: {
                    recipient: deployAddr.address,
                    expirationTime,
                    revocable: true,
                    refUID: ZERO_BYTES32,
                    data,  
                    value: 0
                  }
                })
              ); 

              console.log("Root Key #1 UID: " + rootKey1UID);

              data = (abiCoder.encode(['string','bytes','bytes'],['DerivativeKey2-2',asn1key,'0x08d4bc48bc518c82fb4ad216ef88c11068b3f0c40ba60c255f9e0a7a18382e27654eee6b2283266071567993392c1a338fa0b9f2db7aaab1ba8bf2179808dd34']));
              let request = {
                schema: keySchemaUID,
                data: {
                  recipient: deployAddr.address,
                  expirationTime,
                  revocable: true,
                  refUID: rootKey1UID,
                  data,
                  value: 0
                }
              }
              //Now create a derivative key
              derivedKey1_1UID = await getUIDFromAttestTx(
                EASContract.attest(request)
              );

              console.log("Derived Key #1 UID: " + derivedKey1_1UID);

              data = (abiCoder.encode(['string','bytes','bytes'],['DerivativeKey2-2',asn1key,'0x367bbd2f14741cdb258578a08a6670f6157b0cc6901cb48695a650cb9f4aa66af2b9d106094bbb7d6c77d920645e8587b5a2ed9b7a8731299282c13b66fa8cd3']));

              derivedKey2_1UID = await getUIDFromAttestTx(
                EASContract.attest({
                  schema: keySchemaUID,
                  data: {
                    recipient: testAddr2.address,
                    expirationTime,
                    revocable: true,
                    refUID: rootKey1UID,
                    data,
                    value: 0
                  }
                })
              );

              console.log("Derived Key #2 UID: " + derivedKey2_1UID);

              //Check NFT ownership
              var bal = await keyResolver.connect(deployAddr).balanceOf(testAddr2.address);
              console.log("Test Addr2 Bal: " + bal);
        }
    });

    
    it("Mint ERC721 Using Key Attestation", async function(){
        {
            console.log("Mint Key Attestation");
            const AttestationNFT = await ethers.getContractFactory("DoorAttestation");
            NFTWithAttestation = await AttestationNFT.connect(deployAddr).deploy(rootKey1UID, EASContract.address);

            const TestErc721 = await ethers.getContractFactory("TestErc721");
            TestNft = await TestErc721.connect(deployAddr).deploy();

            console.log("NFT Attestation: " + NFTWithAttestation.address);

            console.log("User Address: " + nftUserAddr.address);

            //let lala = await EASContract.getAttestation(rootKey1UID);
            //console.log("Attn: " + lala);
            //console.log("Root Schema: " + lala.schema);

            console.log("Attempt to mint token 57 from attestation");

            let tx = await NFTWithAttestation.connect(nftUserAddr).mintUsingAttestation(signedAttestation);
            let txRes = await tx.wait();
            console.log("Gas used to mint NFT: ", txRes.gasUsed.toString())

            tx = await TestNft.mint();
            txRes = await tx.wait();
            console.log("Gas used to mint simple NFT: ", txRes.gasUsed.toString())

            //test balance
            expect( await NFTWithAttestation.connect(nftUserAddr).balanceOf(nftUserAddr.address)).equal(1);

            expect( (await NFTWithAttestation.connect(nftUserAddr).ownerOf(57)).toLowerCase()).equal(nftUserAddr.address.toLowerCase());

            console.log("Attempt to mint token 58 from attestation");

            //try to mint 58
            await NFTWithAttestation.connect(nftUserAddr).mintUsingAttestation(signedAttestation58);

            expect( await NFTWithAttestation.connect(nftUserAddr).balanceOf(nftUserAddr.address)).equal(2);

            //60
            await NFTWithAttestation.connect(nftUserAddr).mintUsingAttestation(signedAttestation60);

            expect( await NFTWithAttestation.connect(nftUserAddr).balanceOf(nftUserAddr.address)).equal(3);
        }
    });

    it("Test revocation", async function(){
        {
            console.log("Revoke " + derivedKey1_1UID);

            await EASContract.revoke({ 
                schema: keySchemaUID,
                data: {
                  uid: derivedKey1_1UID,
                  value: 0
                }
              });

        
            //now attempt to mint TokenId 59, signed by key 1 
            console.log("Check that attestation can no longer be used.")
            await expect(NFTWithAttestation.connect(nftUserAddr).mintUsingAttestation(signedAttestation59)).to.be.revertedWith('Attestation issuer key not valid');
              
            var bal = await NFTWithAttestation.connect(nftUserAddr).balanceOf(nftUserAddr.address);

            console.log("Test NFT Bal for User: " + bal);

            //create new key with correct schema and try again

            let keyData = (abiCoder.encode(['string','bytes','bytes'],['DerivativeKey2-2',asn1key,'0x08d4bc48bc518c82fb4ad216ef88c11068b3f0c40ba60c255f9e0a7a18382e27654eee6b2283266071567993392c1a338fa0b9f2db7aaab1ba8bf2179808dd34']));

            console.log("Create new derivate key.");
            let request = {
              schema: keySchemaUID,
              data: {
                recipient: deployAddr.address,
                expirationTime: 0,
                revocable: true,
                refUID: rootKey1UID,
                data: keyData,
                value: 0
              }
            }
            //Now create a derivative key
            derivedKey1_1UID = await getUIDFromAttestTx(
              EASContract.attest(request)
            );

            // "Attempt to mint token 59 with attestation with new derivative key (after revocation)
            await NFTWithAttestation.connect(nftUserAddr).mintUsingAttestation(signedAttestation59);
            expect( await NFTWithAttestation.connect(nftUserAddr).balanceOf(nftUserAddr.address)).equal(4);

        }
    });

    it("Test fetching valid keys", async function(){
      {
        //first fetch resolver address from schema registry
        //You need the SchemaUID for the root key (only 1), and the rootKeyUID for the root attestation 
        //  for the keychain you want to check 
        let schemaReturn = await schemaRegistry.connect(deployAddr).getSchema(keySchemaUID);
        //
        console.log("Resolver Addr: " + schemaReturn.resolver);

        //NB the resolver address could be cached but this is to show method from 1st principles
        const KeyResolverContract = await ethers.getContractFactory("KeyResolver");
        const keyResolverInstance = await KeyResolverContract.attach(schemaReturn.resolver);

        //now find valid keys
        let signingData = await keyResolverInstance.getValidSigningAddresses(rootKey1UID);
        let keys = signingData.signingKeys;

        console.log("Keys: " + keys);

        expect( keys.length == 3, "Should have 3 keys at this stage");
        
        console.log("Revoke a key");

        //revoke a key
        await EASContract.revoke({ 
          schema: keySchemaUID,
          data: {
            uid: derivedKey1_1UID,
            value: 0
          }
        });

        signingData = await keyResolverInstance.getValidSigningAddresses(rootKey1UID);
        keys = signingData.signingKeys;

        console.log("Keys: " + keys);2

        expect( keys.length == 2, "Should have 2 keys at this stage");
       


        //now call valid keys on

        //expect( await NFTWithAttestation.connect(nftUserAddr).balanceOf(nftUserAddr.address)).equal(1);

        //getValidSigningAddresses(bytes32 rootUID)
      }
    });

    it("Test NFT root key transfer and issue derivatives from new account", async function(){
        {
            
        }
    });

    it("Test NFT burn from root account", async function(){
        {
            
        }
    });

    it("Test validity of rootkey (issuer should be same as NFT contract if NFT is ownable)", async function(){
        {
            
        }
    });

    it("Check NFT functionality", async function(){
        {
            
        }
    });

    it("supportInterface", async function(){
      {
          
      }
  });
});