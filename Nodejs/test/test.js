'use strict';
let expect = require('chai').expect;
let xorCrypt = require('../dist/xor-crypt.js');

describe('encryption func test', () => {
    it('should return what was encrypted', () => {
        let {encrypted, e_err} = xorCrypt.encrypt("hello bro!", "cool");
        console.log(`encrypted: ${encrypted} |; err: ${e_err}`);

        let {decrypted, d_err} = xorCrypt.decrypt(encrypted, "cool");
        console.log(`decrypted: ${decrypted} |; err: ${d_err}`);

        expect(decrypted).to.equal("hello bro!");
    });
});