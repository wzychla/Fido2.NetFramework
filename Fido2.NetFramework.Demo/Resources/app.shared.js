/* shared */

/*
 * Base64URL-ArrayBuffer
 * https://github.com/herrjemand/Base64URL-ArrayBuffer
 *
 * Copyright (c) 2017 Yuriy Ackermann <ackermann.yuriy@gmail.com>
 * Copyright (c) 2012 Niklas von Hertzen
 * Licensed under the MIT license.
 *
 */
(function () {
    'use strict';

    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    // Use a lookup table to find the index.
    let lookup = new Uint8Array(256);
    for (let i = 0; i < chars.length; i++) {
        lookup[chars.charCodeAt(i)] = i;
    }

    let encode = function (arraybuffer) {
        let bytes = new Uint8Array(arraybuffer),
            i, len = bytes.length, base64url = '';

        for (i = 0; i < len; i += 3) {
            base64url += chars[bytes[i] >> 2];
            base64url += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
            base64url += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
            base64url += chars[bytes[i + 2] & 63];
        }

        if ((len % 3) === 2) {
            base64url = base64url.substring(0, base64url.length - 1);
        } else if (len % 3 === 1) {
            base64url = base64url.substring(0, base64url.length - 2);
        }

        return base64url;
    };

    let decode = function (base64string) {
        let bufferLength = base64string.length * 0.75,
            len = base64string.length, i, p = 0,
            encoded1, encoded2, encoded3, encoded4;

        let bytes = new Uint8Array(bufferLength);

        for (i = 0; i < len; i += 4) {
            encoded1 = lookup[base64string.charCodeAt(i)];
            encoded2 = lookup[base64string.charCodeAt(i + 1)];
            encoded3 = lookup[base64string.charCodeAt(i + 2)];
            encoded4 = lookup[base64string.charCodeAt(i + 3)];

            bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
            bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
            bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
        }

        return bytes.buffer
    };

    let methods = {
        'decode': decode,
        'encode': encode
    }

    /**
     * Exporting and stuff
     */
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        module.exports = methods;

    } else {
        if (typeof define === 'function' && define.amd) {
            define([], function () {
                return methods
            });
        } else {
            window.base64url = methods;
        }
    }
})();

/*
 * Used: attestation
 */
function preformatMakeCredReq(makeCredReq) {
    /* ----- DO NOT MODIFY THIS CODE ----- */
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id = base64url.decode(makeCredReq.user.id);

    for (let excludeCred of makeCredReq.excludeCredentials) {
        excludeCred.id = base64url.decode(excludeCred.id);
    }

    return makeCredReq;
}

/**
 * Decodes arrayBuffer required fields.
 * Used: assertion
 */
var preformatGetAssertReq = (getAssert) => {
    /* ----- DO NOT MODIFY THIS CODE ----- */
    getAssert.challenge = base64url.decode(getAssert.challenge);

    for (let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }

    return getAssert
}


/**
* Converts PublicKeyCredential into serialised JSON
* Used: attestation
*/
function publicKeyCredentialToJSON(pubKeyCred) {
    /* ----- DO NOT MODIFY THIS CODE ----- */
    if (pubKeyCred instanceof Array) {
        let arr = [];
        for (let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));

        return arr
    }

    if (pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
    }

    if (pubKeyCred instanceof Object) {
        let obj = {};

        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }

        return obj
    }

    return pubKeyCred
}

function addLocalMessage(message) {
    if (message) {
        var messageDiv = document.getElementById('localMessage');
        if (messageDiv) {
            if (messageDiv.style.display == 'none') {
                messageDiv.style.display = 'block';
            }
            messageDiv.innerHTML += message.toString();
        }
    }
}