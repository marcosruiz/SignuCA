//During the test the env variable is set to test
process.env.NODE_ENV = 'test';

var fs = require('fs');
var chai = require('chai');
var mocha = require('mocha');
var should = chai.should();
var expect = chai.expect;
var assert = chai.assert;
var chaiHttp = require('chai-http');
var server = require('../app');

var HttpStatus = require('http-status-codes');
var request = require('supertest');

// openssl should be in Enviroment variables
const ssl = 'openssl';
const path = require('path');
const exec = require('child_process').exec;
var random = generateRandomString(5);

chai.use(chaiHttp);

const binaryParser = function (res, cb) {
    res.setEncoding('binary');
    res.data = '';
    res.on("data", function (chunk) {
        res.data += chunk;
    });
    res.on('end', function () {
        cb(null, new Buffer(res.data, 'binary'));
    });
};

/**
 * Return a String of the length <lenght>
 * @param {number} length - length of random string which return
 * @returns {string}
 */
function generateRandomString(length) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < length; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    return text;
};


describe('Certificates: creation and revocation', function () {
    mocha.before(function (done) {
        done();
    });
    it('It should create a new user certificate', function (done) {
        this.timeout(5000);
        // openssl genrsa 4096 > ca/private/personalkey.pem
        var destKey = __dirname + '/testFiles/myKey.pem';
        var cmd = `${ssl} genrsa 4096 > ${destKey}`;
        const child = exec(cmd, (err, stdout, stderr) => {
            if (err) {
                console.log(stderr);
                return;
            }
            // openssl req -new -key ca/private/personalkey.pem -out personalcert.csr -subj "//C=ES\ST=Zaragoza\L=Zaragoza\O=Signu\OU=Signu\CN=SignuPersonal\emailAddress=sobrenombre@gmail.com"
            var destCsr = __dirname + '/testFiles/myCert.csr';
            cmd = `${ssl} req -new -key ${destKey} -out ${destCsr} -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=SignuTest/emailAddress=test${random}@gmail.com"`
            const child2 = exec(cmd, (err, stdout, stderr) => {
                if (err) {
                    console.log(stderr);
                    return;
                }
                var agent = chai.request.agent(server);
                agent.post('/cert')
                    .attach("csr", fs.readFileSync(destCsr), "csr")
                    .buffer()
                    .parse(binaryParser)
                    .end(function (err, res) {
                        var path = __dirname + "/testFiles";
                        fs.writeFileSync(path + "/myCert.pem", res.body);
                        res.should.have.status(HttpStatus.OK);
                        done();
                    });
            });
        });
    });

    it('It should revoke a user certificate', function (done) {
        var myCertRoute = __dirname + "/testFiles/myCert.pem";
        var agent = chai.request.agent(server);
        agent.get('/revoke')
            .attach("pem", fs.readFileSync(myCertRoute), "pem")
            .end(function (err, res) {
                res.should.have.status(HttpStatus.OK);
                done();
            });
    });

    it('It should create, revoke a certificate', function (done) {
        this.timeout(10000);
        // openssl genrsa 4096 > ca/private/personalkey.pem
        var destKey = __dirname + '/testFiles/myKey.pem';
        var cmd = `${ssl} genrsa 4096 > ${destKey}`;
        const child = exec(cmd, (err, stdout, stderr) => {
            if (err) return;
            // openssl req -new -key ca/private/personalkey.pem -out personalcert.csr -subj "//C=ES\ST=Zaragoza\L=Zaragoza\O=Signu\OU=Signu\CN=SignuPersonal\emailAddress=sobrenombre@gmail.com"
            var destCsr = __dirname + '/testFiles/myCert.csr';
            cmd = `${ssl} req -new -key ${destKey} -out ${destCsr} -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=SignuTest/emailAddress=test${random}@gmail.com"`
            const child2 = exec(cmd, (err, stdout, stderr) => {
                if (err) return;
                var agent = chai.request.agent(server);
                // Create certificate
                agent.post('/cert')
                    .attach("csr", fs.readFileSync(destCsr), "csr")
                    .buffer()
                    .parse(binaryParser)
                    .end(function (err, res) {
                        var path = __dirname + "/testFiles";
                        var myCertRoute = __dirname + "/testFiles/myCert.pem";
                        fs.writeFileSync(myCertRoute, res.body);
                        res.should.have.status(HttpStatus.OK);
                        // Revoke certificate
                        agent.get('/revoke')
                            .attach("pem", fs.readFileSync(myCertRoute), "pem")
                            .end(function (err, res) {
                                res.should.have.status(HttpStatus.OK);
                                done();
                            });
                    });
            });
        });
    });

    it('It should create, revoke a certificate and check CRL', function (done) {
        this.timeout(20000);
        // openssl genrsa 4096 > ca/private/personalkey.pem
        var destKey = __dirname + '/testFiles/myKey.pem';
        var cmd = `${ssl} genrsa 4096 > ${destKey}`;
        const child = exec(cmd, (err, stdout, stderr) => {
            if (err) return;
            // openssl req -new -key ca/private/personalkey.pem -out personalcert.csr -subj "//C=ES\ST=Zaragoza\L=Zaragoza\O=Signu\OU=Signu\CN=SignuPersonal\emailAddress=sobrenombre@gmail.com"
            var destCsr = __dirname + '/testFiles/myCert.csr';
            cmd = `${ssl} req -new -key ${destKey} -out ${destCsr} -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=SignuTest/emailAddress=test${random}@gmail.com"`
            const child2 = exec(cmd, (err, stdout, stderr) => {
                if (err) return;
                var agent = chai.request.agent(server);
                // Create certificate
                agent.post('/cert')
                    .attach("csr", fs.readFileSync(destCsr), "csr")
                    .buffer()
                    .parse(binaryParser)
                    .end(function (err, res) {
                        var path = __dirname + "/testFiles";
                        var myCertRoute = __dirname + "/testFiles/myCert.pem";
                        fs.writeFileSync(myCertRoute, res.body);
                        res.should.have.status(HttpStatus.OK);
                        // Revoke certificate
                        agent.get('/revoke')
                            .attach("pem", fs.readFileSync(myCertRoute), "pem")
                            .end(function (err, res) {
                                res.should.have.status(HttpStatus.OK);
                                agent.get('/ca.crl')
                                    .buffer()
                                    .parse(binaryParser)
                                    .end(function (err, res) {
                                        res.should.have.status(HttpStatus.OK);
                                        var pathCRL = __dirname + '/testFiles/ca.crl';
                                        fs.writeFileSync(pathCRL, res.body);
                                        // Check certificate is revoked
                                        cmd = `${ssl} crl -inform DER -text -noout -in ${pathCRL}`;
                                        const child3 = exec(cmd, (err, stdout, stderr) => {
                                            if (err) {
                                                return next(err);
                                            } else if (stderr != null && stderr != '') {
                                            } else {
                                                // console.log(stdout);
                                                done();
                                            }
                                        });
                                    });
                            });
                    });
            });
        });
    });
});

describe('GET CA Cert', function (done) {
    it('It shold get the CA Cert', function (done) {
        var agent = chai.request.agent(server);
        var pathCaCert = __dirname + '/testFiles/cacert.pem';
        agent.get('/cacert')
            .buffer()
            .parse(binaryParser)
            .end(function (err, res) {
                res.should.have.status(HttpStatus.OK);
                fs.writeFileSync(pathCaCert, res.body);
                done();
            });
    });
});

describe('CRL', function (done) {
    it('It should get a CRL', function (done) {
        var pathCRL = __dirname + '/testFiles/ca.crl';
        var agent = chai.request.agent(server);
        agent.get('/ca.crl')
            .buffer()
            .parse(binaryParser)
            .end(function (err, res) {
                res.should.have.status(HttpStatus.OK);
                fs.writeFileSync(pathCRL, res.body);
                done();
            });
    });
    it('It should get a CRL and check it', function (done) {
        var destCRLDER = __dirname + '/testFiles/crl.der';
        var destCRLPEM = __dirname + '/testFiles/crl.pem';
        var agent = chai.request.agent(server);
        agent.get('/ca.crl')
            .buffer()
            .parse(binaryParser)
            .end(function (err, res) {
                res.should.have.status(HttpStatus.OK);
                fs.writeFileSync(destCRLDER, res.body);
                // We transform DER to PEM
                // openssl crl -inform DER -text -noout -in crl.der -out crl.pem
                var cmd = `${ssl} crl -inform DER -text -noout -in ${destCRLDER} -out ${destCRLPEM}`;
                const child = exec(cmd, (err, stdout, stderr) => {
                    expect(err).to.be.a('null');
                    expect(stderr).to.be.a('string');
                    assert.equal(stderr, '');
                    expect(stdout).to.be.a('string');
                    done();
                });
            });
    });
});

describe('OCSP', function (done) {
    it('It should get a OCSP', function (done) {
        var agent = chai.request.agent(server);
        agent.get('/ocsp')
            .end(function (err, res) {
                res.should.have.status(HttpStatus.OK);
                done();
            });
    });
});
