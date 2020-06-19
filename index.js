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
const fs = require('fs');


global.TTP_PublicKey
global.TTP_PrivateKey
global.claveK
global.TTPcert
global.type4

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

    getCertAndKeys()

});

const io = SocketIO(server);

io.on('connection', (socket) => {

    var userSocket;

    socket.on('usuario', (msg) => {
        console.log('Se ha conectado ' + msg);

        usuarios.set(msg, socket.id);
        userSocket = msg


    });

    socket.on('concejal-to-ttp-type4', async (mensaje) => {

        console.log(mensaje)

    });

    socket.on('alcalde-to-ttp-type1', async (mensaje) => {

        console.log(mensaje)
        
        var aytoCert = await getAytoCert()
        var alcaldeCert = mensaje.cert

        var alcaldePublicKey = await extractPubKFromCert(alcaldeCert, aytoCert)

        if (alcaldePublicKey === null) {
            console.log("No se ha podido verificar que el Ayuntamiento haya emitido el certificado correspondiente")

        } else {


            if (await verifyHash(alcaldePublicKey, mensaje.body, mensaje.pko) == false) {
                console.log("No se ha podido verificar al Alcalde")
            } else {
                var ts = new Date();

                const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);





                var bodyDecreto = {
                    orden: mensaje.body.msg.orden,
                    solicitado: alcaldeCert.cert.ID,
                    decreto_publickey: {
                        e: bigconv.bigintToHex(publicKey.e),
                        n: bigconv.bigintToHex(publicKey.n)
                    }
                }



                const digestDecreto = await digestHash(bodyDecreto);
                const ttpSignatureDecreto = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digestDecreto)));

                var decreto = {
                    Decreto: bodyDecreto,
                    Verificacion_TTP: ttpSignatureDecreto
                }

                const crypto = require('crypto');

                const key = crypto.randomBytes(32)
                const iv = crypto.randomBytes(16)

                let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);

                let encrypted = cipher.update(JSON.stringify(decreto));
                encrypted = Buffer.concat([encrypted, cipher.final()]);
                encryptedData = encrypted.toString('hex')




                var body = {
                    type: '2',
                    src: 'Alcalde',
                    TTP: 'TTP',
                    dest: 'Concejales',
                    msg: {
                        decreto: encryptedData,
                        keyDecreto: {
                            key: bigconv.bigintToHex(publicKey.encrypt(bigconv.bufToBigint(key))),
                            iv: bigconv.bigintToHex(publicKey.encrypt(bigconv.bufToBigint(iv)))
                        }
                    },
                    ts: ts.toUTCString()
                }



                const digestType2 = await digestHash(body);
                const pkp = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digestType2)));


                const type2 = {
                    body: body,
                    pkp: pkp,
                    cert: TTPcert
                }


                socket.emit('ttp-to-alcalde-type2', type2)



                var clavesShamir = await inicioProceso(mensaje.body.msg.key, privateKey)

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


                usuarios.forEach((k, v) => {
                    if (v != "alcalde") {
                        switchType3(v, k, socket)
                    }


                })
            }
        }


    })

    socket.on('disconnect', () => {

        console.log("el usuario " + userSocket + " se ha desconectado ")
        usuarios.delete(userSocket);
    });



});



async function inicioProceso(claveK, prK) {


    var result = [];



    var DecretoPrivateKey = prK;


    var DPrK_d = bigconv.bigintToHex(DecretoPrivateKey.d)
    var DPrK_n = bigconv.bigintToHex(DecretoPrivateKey.publicKey.n)


    const secret_d = Buffer.from(DPrK_d)
    const secret_n = Buffer.from(DPrK_n)

    const share_d = sss.split(secret_d, { shares: 4, threshold: 2 });
    const share_n = sss.split(secret_n, { shares: 4, threshold: 2 });



    for (let i = 0; i < 4; i++) {
        result.push(encrypt(bigconv.bufToHex(share_d[i]), claveK))
        result.push(encrypt(bigconv.bufToHex(share_n[i]), claveK))

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

function encrypt(text, exportedKey) {
    const algorithm = 'aes-256-cbc';
    const key = bigconv.hexToBuf(exportedKey)
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

function getCertAndKeys() {
    var cert = JSON.parse(fs.readFileSync('./certs/ttpCert.json'));

    TTPcert = cert.certificate

    TTP_PublicKey = new rsa.PublicKey(bigconv.hexToBigint(TTPcert.cert.publicKey.e), bigconv.hexToBigint(TTPcert.cert.publicKey.n))
    TTP_PrivateKey = new rsa.PrivateKey(bigconv.hexToBigint(cert.privateKey.d), TTP_PublicKey)


}

async function switchType3(v, k, socket) {
    var ts = new Date();


    switch (v) {
        case "concejal1":
            var body1 = {
                type: '3',
                src: 'Alcalde',
                TTP: 'TTP',
                dest: 'Concejal1',
                msg: mConcejal1,
                ts: ts.toUTCString()
            }

            const digest1 = await digestHash(body1);
            const po1 = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digest1)));

            const bodyToEmit1 = {
                body: body1,
                po: po1,
                cert: TTPcert
            }
            socket.broadcast.to(k).emit('ttp-to-concejal-type3', bodyToEmit1);
            break;

        case "concejal2":
            var body2 = {
                type: '3',
                src: 'Alcalde',
                TTP: 'TTP',
                dest: 'Concejal2',
                msg: mConcejal2,
                ts: ts.toUTCString()
            }

            const digest2 = await digestHash(body2);
            const po2 = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digest2)));

            const bodyToEmit2 = {
                body: body2,
                po: po2,
                cert: TTPcert
            }
            socket.broadcast.to(k).emit('ttp-to-concejal-type3', bodyToEmit2);
            break;

        case "concejal3":
            var body3 = {
                type: '3',
                src: 'Alcalde',
                TTP: 'TTP',
                dest: 'Concejal3',
                msg: mConcejal3,
                ts: ts.toUTCString()
            }

            const digest3 = await digestHash(body3);
            const po3 = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digest3)));

            const bodyToEmit3 = {
                body: body3,
                po: po3,
                cert: TTPcert
            }
            socket.broadcast.to(k).emit('ttp-to-concejal-type3', bodyToEmit3);
            break;

        case "concejal4":
            var body4 = {
                type: '3',
                src: 'Alcalde',
                TTP: 'TTP',
                dest: 'Concejal4',
                msg: mConcejal4,
                ts: ts.toUTCString()
            }

            const digest4 = await digestHash(body4);
            const po4 = bigconv.bigintToHex(TTP_PrivateKey.sign(bigconv.textToBigint(digest4)));

            const bodyToEmit4 = {
                body: body4,
                po: po4,
                cert: TTPcert
            }
            socket.broadcast.to(k).emit('ttp-to-concejal-type3', bodyToEmit4);
            break;
    }
}




//########################################################################################