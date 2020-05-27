const rsa = require('rsa-scii-upc');
const sha = require('object-sha');
const bigconv = require('bigint-conversion');
const fs = require('fs');


global.ttp_pubKey;
global.ttp_prKey;

createKeys();


async function digestHash(body) {
    const d = await sha.digest(body, 'SHA-256');
    return d;
}

async function createKeys() {
    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

    ttp_pubKey = publicKey;
    ttp_prKey = privateKey;

    saveTTPCert()


}

function saveTTPCert() {

    var cert = {
        publicKey: {
            e: bigconv.bigintToHex(ttp_pubKey.e),
            n: bigconv.bigintToHex(ttp_pubKey.n)
        },
        IssuerID: "TTP",
    }
    
    var signatureIssuer = bigconv.bigintToHex(ttp_prKey.sign(bigconv.textToBigint(digestHash(cert))));
    
    var certificate = {
        certificate: {
            cert, signatureIssuer
        },
        privateKey: {
            d: bigconv.bigintToHex(ttp_prKey.d),
            n: bigconv.bigintToHex(ttp_prKey.publicKey.n)
        }
    }

    fs.writeFileSync("./certs/ttpCert.json", JSON.stringify(certificate))


}



    



