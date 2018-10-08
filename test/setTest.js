//During the test the env variable is set to test
process.env.NODE_ENV = 'test';

var fs = require('fs');
var chai = require('chai');
var mocha = require('mocha');
var should = chai.should();
var chaiHttp = require('chai-http');
var server = require('../app');

var HttpStatus = require('http-status-codes');
var request = require('supertest');

// openssl should be in Enviroment variables
const ssl = 'openssl.exe';
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



describe('Certs', function () {
    mocha.before(function(done){
        var random = generateRandomString(5);
        done();
    });
    it('It should create a new user certificate', function (done) {
        this.timeout(5000);

        // openssl genrsa 4096 > ca/private/personalkey.pem
        var destKey = __dirname + '\\testFiles\\myKey.pem';
        var cmd = `${ssl} genrsa 4096 > ${destKey}`;
        const child = exec(cmd, (err, stdout, stderr) => {
            if (err) return;
            // openssl req -new -key ca/private/personalkey.pem -out personalcert.csr -subj "//C=ES\ST=Zaragoza\L=Zaragoza\O=Signu\OU=Signu\CN=SignuPersonal\emailAddress=sobrenombre@gmail.com"
            var destCsr = __dirname + '\\testFiles\\myCert.csr';
            cmd = `${ssl} req -new -key ${destKey} -out ${destCsr} -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=SignuTest/emailAddress=test${random}@gmail.com"`
            const child2 = exec(cmd, (err, stdout, stderr) => {
                if (err) return;
                var agent = chai.request.agent(server);
                agent.post('/cert')
                    .attach("csr", fs.readFileSync(destCsr), "csr")
                    .buffer()
                    .parse(binaryParser)
                    .end(function (err, res) {
                        var path = __dirname + "\\testFiles";
                        fs.writeFileSync(path + "\\myCert.pem", res.body);
                        res.should.have.status(HttpStatus.OK);
                        done();
                    });
            });
        });
    });
    it('It should create and revoke a user certificate', function (done) {
        var myCertRoute = __dirname + "\\testFiles\\myCert.pem";
        var agent = chai.request.agent(server);
        agent.get('/revoke')
            .attach("pem", fs.readFileSync(myCertRoute), "pem")
            .end(function (err, res) {
                res.should.have.status(HttpStatus.OK);
                done();
            });
    });
    it('It should get ', function (done) {
        done();
    });
    it('fds', function (done) {
        done();
    });
});