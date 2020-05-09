const express = require('express');
const app = express();
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const bigconv = require('bigint-conversion');
const sha = require('object-sha');
const crypto = require('crypto');
const rsa = require('rsa-scii-upc');
const sss = require('shamirs-secret-sharing')
const ___dirname = path.resolve();

global.TTP_PublicKey
global.TTP_PrivateKey
global.claveK


async function claveRSA() {

    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

    TTP_PublicKey = publicKey;
    TTP_PrivateKey = privateKey;


}

async function inicioProceso() {

    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

    var DecretoPrivateKey = privateKey;

    console.log(DecretoPrivateKey);

}


app.post("/type1", async (req, res) => {

    alcadePublicKey = new rsa.PublicKey(bigconv.hexToBigint(req.body.mensaje.e), bigconv.hexToBigint(req.body.mensaje.n));

    // FALTA LA RECEPCIÓN DE LA CLAVE K A FALTA DE QUE SE GENERE EL CÓDIGO EN EL CLIENTE

    if (await verifyHash(alcadePublicKey, req.body.mensaje.body, req.body.mensaje.body) == true) {

        var ts = new Date();

        const body = {
            type: '2',
            src: 'Alcalde',
            dst: 'Cn',
            ttp: 'TTP',
            ts: ts.getHours(),
        }

        const digest = await digestHash(body);

        const pkp = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digest)));

        res.status(200).send({
            body, pkp
        });

    } else {
        res.status(400).send("No se ha podido verificar al Alcalde");
    }

});


async function inicioProceso() {

    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

    var DecretoPrivateKey = privateKey;

    var DPrK_d = bigconv.bigintToText(DecretoPrivateKey.d)
    var DPrK_n = bigconv.bigintToText(DecretoPrivateKey.publicKey.n)

    const secret_d = Buffer.from(DPrK_d)
    const secret_n = Buffer.from(DPrK_n)

    const share_d = sss.split(secret_d, {shares: 4, threshold: 2});
    const share_n = sss.split(secret_n, {shares: 4, threshold: 2});

    var concejal1 = bigconv.bufToHex(share_d[0]);

    console.log(concejal1)

}



async function verifyHash(PublicKey, body, signature) {
    const hashBody = await sha.digest(body, 'SHA-256')
    var verify = false;

    if (hashBody == bigconv.bigintToText(PublicKey.verify(bigconv.hexToBigint(signature)))) {
        verify = true
    }
    return verify
}

async function digestHash(body) {
    const d = await sha.digest(body, 'SHA-256');
    return d;
}




//########################## CONFIF SERVIDOR ############################################

// settings
app.set('port', process.env.PORT || 8000);
app.set('json spaces', 2);

// middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

// routes

// starting the server
app.listen(app.get('port'),() => {
    claveRSA()
    inicioProceso()
    console.log(`Server on port ${app.get('port')}`);

});

//########################################################################################