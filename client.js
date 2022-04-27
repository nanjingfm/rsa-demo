const NodeRSA = require('node-rsa');
const fs = require('fs')
let publicKeyData = ""
try {
    publicKeyData = fs.readFileSync("pub.key", 'utf-8')
} catch (err) {
    console.error(err)
}

console.log("公钥：\n", publicKeyData)
const key = new NodeRSA(publicKeyData, 'pkcs8-public-pem', {
    encryptionScheme: 'pkcs1',
    environment: 'node',
})
const encryptData = key.encrypt("11234567890", 'base64', 'utf8')
console.log("密文：\n", encryptData)
