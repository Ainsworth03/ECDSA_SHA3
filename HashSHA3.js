/*
FEBRIAN NASHRULLAH
2100830
SHA3-256
=====================================================
*/

//curve: x^3 + ax + b mod r

const {sha3_256} = require('js-sha3')

/** Find hash SHA3-256 of the message
 * 
 * @param {string} message - message to hash
 * @returns {hash_result} result of hash SHA3-256
 */
const findHash = (message) => {
    const hash_result = sha3_256(message)
    const hash_int = BigInt("0x" + hash_result)
    console.log(hash_result)
    console.log(hash_int)
    return hash_int 
}

module.exports =  {findHash}