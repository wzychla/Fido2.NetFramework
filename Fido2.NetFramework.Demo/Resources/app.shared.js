/* shared */

(function () {
    var encode = function (arraybuffer) {
        const binString = String.fromCodePoint(...new Uint8Array(arraybuffer));
        return btoa(binString);
    }

    var decode = function (base64string) {
        base64string = base64string.replace("-", "+").replace("_", "/"); // fix na niedekodujący się _
        const binString = atob(base64string);
        return Uint8Array.from(binString, (m) => m.codePointAt(0));
    }

    window.base64url = { decode, encode };
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