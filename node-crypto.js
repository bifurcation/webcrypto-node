var crypto = require('crypto');
var events = require('events');
var util = require('util');

var abvutil = {
    abv2u8: function(abv) {
        return new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
    },

    abv2str: function(abv) {
        var str = "";
        u8a = abvutil.abv2u8(abv);
        for (var i=0; i<u8a.length; ++i) {
            str += String.fromCharCode(u8a[i]);
        }
        return str;
    },

    str2abv: function(str) {
        var u8a = new Uint8Array(str.length);
        for (var i=0; i<u8a.length; ++i) {
            u8a[i] += str.charCodeAt(i);
        }
        return u8a;
    }
};

function normalizeAlgorithm(aAlgorithm) {
    var algorithm = aAlgorithm;
    /* TODO normalization */
    if (typeof(aAlgorithm) === "string") {
        algorithm = { name: algorithm };
    }
    return algorithm;
}

var ABORT = "abort";
var ERROR = "error";
var PROGRESS = "progress";
var COMPLETE = "complete";

function CryptoOperation() {
    events.EventEmitter.call(this);
    Object.defineProperty(this, "onabort",    { set: function(fn) { this.on(ABORT, fn); } });
    Object.defineProperty(this, "onerror",    { set: function(fn) { this.on(ERROR, fn); } });
    Object.defineProperty(this, "onprogress", { set: function(fn) { this.on(PROGRESS, fn); } });
    Object.defineProperty(this, "oncomplete", { set: function(fn) { this.on(COMPLETE, fn); } });
}
util.inherits(CryptoOperation, events.EventEmitter);

function KeyOperation() {
    events.EventEmitter.call(this);
}
KeyOperation.prototype = {
    set onerror(fn)    { console.log("Set!"); this.on(ERROR, fn); },
    set oncomplete(fn) { console.log("Set!"); this.on(COMPLETE, fn); },
};
util.inherits(KeyOperation, events.EventEmitter);


function EncryptOperation(aAlgorithm, aKey, aBuffer) {
    var algorithm = normalizeAlgorithm(aAlgorithm);

    // Make sure the IV is present, and convert it to a string
    if (!algorithm.iv) { throw "IV required"; }
    var key = aKey._data.k;
    var iv = abvutil.abv2str(algorithm.iv);
    var buffer = "";

    // Choose a cipher
    var cipher = null
    switch (algorithm.name) {
        case "AES-CBC":
            switch (key.length) {
                case 16: cipher = crypto.createCipheriv("AES-128-CBC", key, iv); break;
                case 24: cipher = crypto.createCipheriv("AES-192-CBC", key, iv); break;
                case 32: cipher = crypto.createCipheriv("AES-256-CBC", key, iv); break;
            }
            break;
        case "AES-CFB":
            switch (key.length) {
                case 16: cipher = crypto.createCipheriv("AES-128-CFB", key, iv); break;
                case 24: cipher = crypto.createCipheriv("AES-192-CFB", key, iv); break;
                case 32: cipher = crypto.createCipheriv("AES-256-CFB", key, iv); break;
            }
            break;
    }
    
    // Interface CryptoOperation
    this.key = null;
    this.algorithm = algorithm;
    this.result = null;
    this.process = function(aBuffer) {
        buffer += cipher.update(abvutil.abv2str(aBuffer), "binary", "binary");
        /* TODO fire progress event */
        return this;
    }; 
    this.finish = function() {
        buffer += cipher.final("binary");
        this.result = abvutil.str2abv(buffer);
        /* TODO fire complete event */
        return this;
    }; 
    this.abort = function() { /* NOP */ };

    if (aBuffer) {
        this.process(aBuffer);
        this.finish();
    }

    return this;
}
EncryptOperation.prototype = new CryptoOperation();


function DecryptOperation(aAlgorithm, aKey, aBuffer) {
    var algorithm = normalizeAlgorithm(aAlgorithm);

    // Make sure the IV is present, and convert it to a string
    if (!algorithm.iv) { throw "IV required"; }
    var key = aKey._data.k;
    var iv = abvutil.abv2str(algorithm.iv);
    var buffer = "";

    // Choose a cipher
    var cipher = null
    switch (algorithm.name) {
        case "AES-CBC":
            switch (key.length) {
                case 16: cipher = crypto.createDecipheriv("AES-128-CBC", key, iv); break;
                case 24: cipher = crypto.createDecipheriv("AES-192-CBC", key, iv); break;
                case 32: cipher = crypto.createDecipheriv("AES-256-CBC", key, iv); break;
            }
            break;
        case "AES-CFB":
            switch (key.length) {
                case 16: cipher = crypto.createDecipheriv("AES-128-CFB", key, iv); break;
                case 24: cipher = crypto.createDecipheriv("AES-192-CFB", key, iv); break;
                case 32: cipher = crypto.createDecipheriv("AES-256-CFB", key, iv); break;
            }
            break;
    }
    
    // Interface CryptoOperation
    this.key = null;
    this.algorithm = algorithm;
    this.result = null;
    this.process = function(aBuffer) {
        buffer += cipher.update(abvutil.abv2str(aBuffer), "binary", "binary");
        /* TODO fire progress event */
        return this;
    }; 
    this.finish = function() {
        buffer += cipher.final("binary");
        this.result = abvutil.str2abv(buffer);
        /* TODO fire complete event */
        return this;
    }; 
    this.abort = function() { /* NOP */ };

    if (aBuffer) {
        this.process(aBuffer);
        this.finish();
    }

    return this;
}
DecryptOperation.prototype = new CryptoOperation();



function DigestOperation(aAlgorithm, aBuffer) {
    var algorithm = normalizeAlgorithm(aAlgorithm);

    // Choose digest implementation
    var hash = null;
    switch (algorithm.name) {
        case "SHA-1":   hash = crypto.createHash("SHA1");    break;
        case "SHA-224": hash = crypto.createHash("SHA224"); break;
        case "SHA-256": hash = crypto.createHash("SHA256"); break;
        case "SHA-384": hash = crypto.createHash("SHA384"); break;
        case "SHA-512": hash = crypto.createHash("SHA512"); break;
    }
    if (!hash) {
        throw "Unable to create hash function";
    }

    // Interface CryptoOperation
    this.key = null;
    this.algorithm = algorithm;
    this.result = null;
    this.process = function(aBuffer) {
        hash.update(abvutil.abv2str(aBuffer), "binary");
        /* TODO fire progress event */
        return this;
    }; 
    this.finish = function() {
        this.result = abvutil.str2abv(hash.digest("binary"));
        /* TODO fire complete event */
        this.emit(COMPLETE, this);
        return this;
    }; 
    this.abort = function() { /* NOP */ };

    if (aBuffer) {
        this.process(aBuffer);
        this.finish();
    }

    return this;
}
DigestOperation.prototype = new CryptoOperation();


function ImportKeyOperation(aFormat, aKeyData, aAlgorithm, aExtractable, aKeyUsages) {
    var algorithm = normalizeAlgorithm(aAlgorithm);

    // Construct a key object
    // NB: Not doing any separation here
    var key = {};
    switch (aFormat) {
        case "raw": 
            key["_data"] = { k: abvutil.abv2str(aKeyData) };
            key["type"] = "secret";
        default: throw "Unsupported key format";
    }
    key["extractable"] = aExtractable;
    key["algorithm"] = aAlgorithm;
    key["keyUsage"] = aKeyUsages;
    
    // Interface KeyOperation
    this.result = key;

    return this;
}
ImportKeyOperation = new KeyOperation();


function ExportKeyOperation(aFormat, aKey) {
    var algorithm = normalizeAlgorithm(aAlgorithm);

    if (!aKey.extractable) {
        // TODO: Fail better
        return;
    }

    // Construct a key object
    // NB: Not doing any separation here
    var key = {};
    switch (aFormat) {
        case "raw": 
            key = abvutil.str2abv(aKey._data.k);
        default: throw "Unsupported key format";
    }
    
    // Interface KeyOperation
    this.result = key;

    return this;
}
ExportKeyOperation = new KeyOperation();


// Crypto Operations
exports.encrypt = function(alg, key, buf) { return new EncryptOperation(alg, key, buf); };
exports.decrypt = function(alg, key, buf) { return new DecryptOperation(alg, key, buf); };
// exports.sign = function(alg, key, buf) { return new SignOperation(alg, key, buf); };
// exports.verify = function(alg, key, buf) { return new VerifyOperation(alg, key, buf); };
exports.digest  = function(alg, buf) { return new DigestOperation(alg, buf); };

// Key Operations
// exports.deriveKey   = DeriveKeyOperation;
// exports.generateKey = GenerateKeyOperation;
exports.importKey   = function(fmt, key, alg, ext, use) { return new ImportKeyOperation(fmt, key, alg, ext, use); };
exports.exportKey   = function(fmt, key) { return new ExportKeyOperation(type, key); };

