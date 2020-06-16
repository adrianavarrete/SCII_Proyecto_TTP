const express = require('express');
const SocketIO = require('socket.io');
const app = express();
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const bigconv = require('bigint-conversion');
const sha = require('object-sha');
const crypto = require('crypto');
const rsa = require('rsa-scii-upc');
const sss = require('shamirs-secret-sharing')
const request = require('request');
const ___dirname = path.resolve();
const HashMap = require('hashmap');

global.TTP_PublicKey
global.TTP_PrivateKey
global.claveK

var usuarios = new HashMap();


//########################## CONFIF SERVIDOR ############################################

// settings
app.set('port', process.env.PORT || 9000);
app.set('json spaces', 2);

// middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

// routes

// starting the server
const server = app.listen(app.get('port'), () => {
    console.log(`Server on port ${app.get('port')}`);

});

const io = SocketIO(server);

io.on('connection', (socket) => {

    var userSocket;

    socket.on('usuario', (msg) => {
        console.log('Se ha conectado ' + msg);

        usuarios.set(msg, socket.id);
        userSocket = msg


    });

    socket.on('alcalde-to-ttp-type1', async (mensaje) => {

        var aytoCert = await getAytoCert()
        var alcaldeCert = mensaje.cert

        var alcaldePublicKey = await extractPubKFromCert(alcaldeCert, aytoCert)

        if (alcaldePublicKey === null) {
            console.log("No se ha podido verificar que el Ayuntamiento haya emitido el certificado correspondiente")

        } else {


            if (await verifyHash(alcaldePublicKey, mensaje.body, mensaje.pko) == false) {
                console.log("No se ha podido verificar al Alcalde")
            } else {

                var clavesShamir = await inicioProceso(mensaje.body.msg)

                //llamar a la función para procesar el paquete de entrada y generar el type2

                socket.emit('ttp-to-alcalde-type2', 'type2')

                //llamar a la funcion que genera shamir

                mConcejal1 = {
                    d: clavesShamir[0],
                    n: clavesShamir[1]
                }
                mConcejal2 = {
                    d: clavesShamir[2],
                    n: clavesShamir[3]
                }
                mConcejal3 = {
                    d: clavesShamir[4],
                    n: clavesShamir[5]
                }
                mConcejal4 = {
                    d: clavesShamir[6],
                    n: clavesShamir[7]
                }

            }
        }








        usuarios.forEach((k, v) => {
            console.log(k)
            if (v != "alcalde") {
                switch (v) {
                    case "concejal1":
                        socket.broadcast.to(k).emit('ttp-to-concejal-type4', mConcejal1);
                        break;
                    case "concejal2":
                        socket.broadcast.to(k).emit('ttp-to-concejal-type4', mConcejal2);
                        console.log("HOLA")
                        break;
                    case "concejal3":
                        socket.broadcast.to(k).emit('ttp-to-concejal-type4', mConcejal3);
                        break;
                    case "concejal4":
                        socket.broadcast.to(k).emit('ttp-to-concejal-type4', mConcejal4);
                        break;
                }

            }


        })


    })

    socket.on('disconnect', () => {

        console.log("el usuario " + userSocket + " se ha desconectado ")
        usuarios.delete(userSocket);
    });



});


async function claveRSA() {

    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

    TTP_PublicKey = publicKey;
    TTP_PrivateKey = privateKey;


}

async function inicioProceso(claveK) {

    console.log(claveK)

    var result = [];

    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

    var DecretoPrivateKey = privateKey;

    var DPrK_d = bigconv.bigintToText(DecretoPrivateKey.d)
    var DPrK_n = bigconv.bigintToText(DecretoPrivateKey.publicKey.n)

    const secret_d = Buffer.from(DPrK_d)
    const secret_n = Buffer.from(DPrK_n)

    const share_d = sss.split(secret_d, { shares: 4, threshold: 2 });
    const share_n = sss.split(secret_n, { shares: 4, threshold: 2 });

    //Falta encriptar con la clave recibida por el Alcalde

    for (let i = 0; i < 4; i++) {
        result.push(encrypt(bigconv.bufToHex(share_d[i])))
        result.push(encrypt(bigconv.bufToHex(share_n[i])))

    }

    return result;

}

async function extractPubKFromCert(cert, issuerCert) {
    const hashBody = await sha.digest(cert.cert, 'SHA-256')
    var issuerPublicKey = new rsa.PublicKey(bigconv.hexToBigint(issuerCert.cert.publicKey.e), bigconv.hexToBigint(issuerCert.cert.publicKey.n))

    if (hashBody == bigconv.bigintToText(issuerPublicKey.verify(bigconv.hexToBigint(cert.signatureIssuer)))) {

        return new rsa.PublicKey(bigconv.hexToBigint(cert.cert.publicKey.e), bigconv.hexToBigint(cert.cert.publicKey.n))

    } else {
        return null
    }

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

function encrypt(text) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

async function getAytoCert() {

    return new Promise((resolve, reject) => {
        request.get('http://localhost:3000/AytoCert', { json: true }, (err, res, body) => {
            if (err) reject(err)
            else {
                resolve(res.body);
            }
        })
    });


}

async function alcaldeToTTPType1() {

    alcadePublicKey = new rsa.PublicKey(bigconv.hexToBigint(mensaje.e), bigconv.hexToBigint(mensaje.n));

    // FALTA LA RECEPCIÓN DE LA CLAVE K A FALTA DE QUE SE GENERE EL CÓDIGO EN EL CLIENTE

    if (await verifyHash(alcadePublicKey, req.body.mensaje.body, req.body.mensaje.body) == true) {

        var ts = new Date();

        const body = {
            type: '2',
            src: 'Alcalde',
            dst: 'Cn',
            ttp: 'TTP',
            ts: ts.toUTCString()
        }

        const digest = await digestHash(body);

        const pkp = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digest)));

        socket.emit('ttp-to-alcalde-type2', {
            body, pkp
        });

        // recorrer un bucle para ver todos los concejales y sus sockets ID

        socket.broadcast.to(usuarios.get("Alcalde")).emit('mensaje-to-alcalde', mensaje)





    } else {
        socket.emit('ttp-to-alcalde-type2', "Not verified");
    }




}


//########################################################################################