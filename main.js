/*
FEBRIAN NASHRULLAH
febrian031318@gmail.com
SHA3-256
=====================================================
*/



const { findHash } = require('./HashSHA3')
const {signing, verifying} = require('./ECDSA')
const { generateKey } = require('./ECDSA')
const {pointAdd, pointMulti, GenerateRandomNum} = require('./ECDSA')
const readline = require('readline');
// const { Hash } = require('crypto');

/*for communicate with smart contract and blockchain
const Web3 = require('web3');
const web3 = new Web3('http://localhost:7545');  // Or your network URL
const contractAddress = '0xYourContractAddress';
const contractABI = [ /* Your contract ABI */ /*];
const contract = new web3.eth.Contract(contractABI, contractAddress);
*/

// Setup the curve
const mod = BigInt(17)
const curve = [BigInt(2), BigInt(2)]
const base_point = [BigInt(5), BigInt(1)]
const order = BigInt(19)

// Setup readline to get user input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

function userInput(query){
    return new Promise(resolve => rl.question(query, resolve))
}

async function menuChoice() {
    try {
        console.log("Menu:\n[1]Signing\n[2]Veryfying\n")
        const action = await userInput("Choose menu: ")
        return action
    }catch (err){
        console.error('Error', err)
    }
    
}

async function signerInput(){
    try {
        const message = await userInput("Message to sign: ")
        const privKey = await userInput("Input your private key: ")
        const pubKey = await generateKey(BigInt(privKey), base_point, mod, curve[0])
        console.log(`message ${message}, privKey ${privKey}`)
        const signerInfo = [message, privKey, pubKey]
        return signerInfo
    }catch (err){
        console.error('Error', err)
    }finally{
        rl.close()
    }
}

async function verifierInput(){
    try{
        const message = await userInput("Message: ")
        const pubKey_a  = await userInput("public key a (pubKey format [a,b]): ")
        const pubKey_b = await userInput("public key b (pubKey format [a,b]): ")
        const signed_r = await userInput("signed a: ")
        const signed_s = await userInput("signed s: ")
        const pubKey = [BigInt(pubKey_a), BigInt(pubKey_b)]
        const signed = [BigInt(signed_r), BigInt(signed_s)]
        const verifierInfo = [message, pubKey, signed]
        return verifierInfo
    }catch (err){
        console.error('Error', err)
    }finally{
        rl.close()
    }
}



// Hashing and Signing
function hashSigning(signerInfo){
    // Hashing:
    const hash = findHash(signerInfo[0])

    // Signing:
    const randomNum = GenerateRandomNum(order)
    //console.log(signerInfo)
    const privKey = BigInt(signerInfo[1])
    const sign = signing(pointMulti, base_point, mod, curve[0], order, privKey, hash, randomNum)

    console.log(`message ${signerInfo[0]} \nhash ${hash} \nSign ${sign} \npubKey ${signerInfo[2]}`)
    return sign
}

function messageVeryfying(verifierInfo){
    const hash = findHash(verifierInfo[0])
    const verified = verifying(pointMulti, base_point, order, verifierInfo[1], verifierInfo[2], hash, mod, curve[0])
    if (verified == true){
        console.log('message validated!')
    }else{
        console.log('message not valid')
    }
}

//Put it all together
async function main(){
    const menu = await menuChoice()
    if (menu == 1){
        let signerInfo = await signerInput()
        let sign = hashSigning(signerInfo)
        console.log(`sign ${sign}`)        
    }else if (menu == 2){
        let verifierInfo = await verifierInput()
        let verify = messageVeryfying(verifierInfo)
    }else{
        console.log("menu = Wrong")
    }

}

main()

