const express = require('express');
var router = express.Router();
const http = require('http');
const fs = require('file-system');
const ssl = 'openssl';
const path = require('path');
const exec = require('child_process').exec;
var HttpStatus = require('http-status-codes');

const cacert = path.resolve(__dirname, '../openssl/ca/cacert.pem');
const cakey = path.resolve(__dirname, '../openssl/ca/private/cakey.pem');
const config = path.resolve(__dirname, '../openssl/openssl.cnf');
const crl = path.resolve(__dirname, '../openssl/ca/crl/ca.crl');
const crlPem = path.resolve(__dirname, '../openssl/ca/crl/ca.crl.pem');

router.get('/', function (req, res) {
    res.send('Welcome to Signu CA');
});

router.post('/cert', processCSR);

router.get('/cacert', function (req, res, next) {
    res.download(cacert, 'cacert.pem');
});

router.get('/ocsp', function (req, res) {
    res.send("Welcome to GET OCSP");
});

router.post('/ocsp', postOCSP);

router.get('/ca.crl', getCRL);

router.get('/revoke', revokeCert);


/**
 * Process a Certificate Signing Request .CSR and return a .PEM
 * Sign
 * @param req
 * @param res
 * @param next
 */
function processCSR(req, res, next) {
    req.on('data', function (data) {
        fs.writeFileSync('file.csr', data);
    });
    req.on('end', function () {
        generateCSRReply('file.csr', function (err, reply) {
            if (err) {
                res.status(500).send("Internal error");
            } else {
                res.header('Content-Disposition', 'attachment; filename=file.pem');
                res.download(reply, 'file.pem');
            }
        });
    });
}

/**
 * Generates a .PEM certificate signed by server
 * @param query
 * @param callback
 */
function generateCSRReply(query, callback) {
    const dirname = path.dirname(query);
    const basename = path.basename(query, path.extname(query));
    const reply = path.resolve(dirname, `${basename}.pem`);
    const queryRoute = path.resolve(dirname, `${basename}.csr`);
    // openssl ca -in personalcert.csr -config openssl.cnf -out ca/newcerts/personalcert.pem
    const cmd = `${ssl} ca -batch -in ${queryRoute} -config ${config} -out ${reply}`;
    const child = exec(cmd, (err, stdout, stderr) => {
        if (err) {
            callback(err);
        } else {
            console.log(stdout);
            callback(null, reply);
        }
    });
}


/**
 * It revokes a cert
 * @param req
 * @param res
 * @param next
 */
function revokeCert(req, res, next) {
    // Get cert
    req.on('data', function (data) {
        fs.writeFileSync('certToRevoke.pem', data);
    });
    req.on('end', function () {
        // Revoke certificate
        // openssl ca -config openssl.cnf -revoke ca/personalcert.pem -keyfile ca/private/cakey.pem -cert ca/cacert.pem
        var cmd = `${ssl} ca -config ${config} -revoke certToRevoke.pem -keyfile ${cakey} -cert ${cacert}`;
        const child = exec(cmd, (err, stdout, stderr) => {
            if (err) return next(err);
            res.status(HttpStatus.OK).send();
        });
    });
}

/**
 * Returns Current Revocation List
 * @param req
 * @param res
 * @param next
 */
function getCRL(req, res, next) {
    // Update CRL
    // openssl ca -config openssl.cnf -gencrl -out ca/crl/ca.crl.pem
    // openssl crl -inform PEM -in ca/crl/ca.crl.pem -outform DER -out ca/crl/ca.crl
    var cmd = `${ssl} ca -config ${config} -gencrl -out ${crlPem}`;
    const child = exec(cmd, (err, stdout, stderr) => {
        if (err) return next(err);
        cmd = `${ssl} crl -inform PEM -in ${crlPem} -outform DER -out ${crl}`;
        const child2 = exec(cmd, (err, stdout, stderr) => {
            if (err) return next(err);
            // Send CRL
            res.header('Content-Disposition', 'attachment; filename=ca.crl');
            res.header('content-type', 'application/pkix-crl');
            res.status(HttpStatus.OK).download(crl, 'ca.crl');
        });
    });
}

/**
 * check this with: openssl ocsp
 */
function postOCSP(req, res) {
    if (req.header('content-type') != 'application/ocsp-request') {
        res.status(HttpStatus.BAD_REQUEST).send("Bad Request");
    } else {
        req.on('data', function (data) {
            fs.writeFileSync('file.ocsp', data);
            console.log(data);
        });
        req.on('end', function () {
            console.log("ocsp");
            res.header('content-type', 'application/ocsp-response');
            res.status(200).send("TODO");
        });
    }
}

var serviceCallback = function (response) {
    return function (err, obj) {
        console.log(response);
        if (err) {
            response.send(500);
        } else {
            response.send(obj);
        }
    }
};

module.exports = router;
