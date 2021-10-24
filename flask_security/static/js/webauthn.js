/**
 * Thanks to duo-labs/py_webauthn - this is their OLD flask demo.
 * Modified accordingly...
 * This code should be considered to be licensed:
 * Copyright (c) 2017 Duo Security, Inc. All rights reserved.
 * with the BSD 3-Clause "New" or "Revised" License.
 */


function b64enc(buf) {
    return base64js.fromByteArray(buf)
                   .replace(/\+/g, "-")
                   .replace(/\//g, "_")
                   .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function fetch_json(url, options) {
    const response = await fetch(url, options);
    const body = await response.json();
    if (body.fail)
        throw body.fail;
    return body;
}

/*
 * Flask-Security API JSON response has:
 * ["response"]["error"] = str OR
 * ["response"]["errors"]["<field_name>"] = list of str
 *
 * Given a response - look for errors - and return True if there were some.
 */
function display_errors(response, id) {
  if (!("error" in response) && !("errors" in response)){
    return false
  }
  const error_element = document.getElementById(id)
  if (error_element) {
    if ("error" in response) {
      error_element.innerHTML = `<b>ERROR</b>: <em>${response["error"]}</em`
    } else if ("errors" in response) {
      error_element.innerHTML = "<b>ERRORS</b>:<ul>"
      for (const field_name in response["errors"]) {
        error_element.innerHTML += `<li>${field_name}: <em>${response["errors"][field_name][0]}</em></li>`
      }
      error_element.innerHTML += "</ul>"
    }
  }
  return true
}

/**
 * REGISTRATION FUNCTIONS
 */

/**
 * Callback after the registration form is submitted.
 * @param {Event} e
 */
const didClickRegister = async (e) => {
    e.preventDefault();

    // gather the data in the form
    const form = document.querySelector('#wan-register-form');
    const formData = new FormData(form);

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    let credentialCreateOptionsFromServer, csrf_token;
    try {
        const resp = await getCredentialCreateOptionsFromServer(
          formData.get('url'),
          formData);
        if (display_errors(resp["response"], "wan-error")) {
          return
        }
        csrf_token = resp["response"]["csrf_token"]
        credentialCreateOptionsFromServer = JSON.parse(resp["response"]["credential_options"]);
    } catch (err) {
        return console.error("Failed to generate credential request options:", err);
    }

    // convert certain members of the PublicKeyCredentialCreateOptions into
    // byte arrays as expected by the spec.
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);

    // request the authenticator(s) to create a new credential keypair.
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        return console.error("Error creating credential:", err);
    }

    // we now have a new credential! We now need to encode the byte arrays
    // in the credential into strings, for posting to our server.
    const newAssertionForServer = transformNewAssertionForServer(credential);

    // post the transformed credential data to the server for validation
    // and storing the public key
    try {
        const resp = await postNewAssertionToServer(
          formData.get('name'),
          csrf_token,
          formData.get('response_url'),
          newAssertionForServer);
        if (display_errors(resp["response"], "wan-error")) {
          return
        }
    } catch (err) {
        return console.error("Server validation of credential failed:", err);
    }

    // reload the page after a successful result
    window.location.reload();
}

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData
 */
const getCredentialCreateOptionsFromServer = async (url, formData) => {
    return await fetch_json(
        url,
        {
            method: "POST",
            body: formData,
            headers: {
              "Accept": "application/json"
            },
        }
    );
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));

    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user});

    return transformedCredentialCreateOptions;
}

/**
 * Transforms the binary data in the credential into base64 strings
 * for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);

    const registrationClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        response: {"attestationObject": b64enc(attObj), "clientDataJSON": b64enc(clientDataJSON)},
        extensions: JSON.stringify(registrationClientExtensions)
    };
}

/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer
 */
const postNewAssertionToServer = async (name, csrf_token, response_url, credentialDataForServer) => {
    credentialDataForServer['name'] = name;
    credentialDataForServer["csrf_token"] = csrf_token

    return await fetch_json(
        response_url, {
        method: "POST",
        body: JSON.stringify(credentialDataForServer),
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
    });
}



/**
 * AUTHENTICATION FUNCTIONS
 */


/**
 * Callback executed after submitting login form
 * @param {Event} e
 */
const didClickLogin = async (e) => {
    e.preventDefault()
    // gather the data in the form
    const form = document.querySelector('#wan-signin-form')
    const formData = new FormData(form)

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialRequestOptionsFromServer, csrf_token
    try {
      const resp = await getCredentialRequestOptionsFromServer(formData.get('url'), formData)
        if (display_errors(resp["response"], "wan-error")) {
          return
        }
        csrf_token = resp["response"]["csrf_token"]
        credentialRequestOptionsFromServer = JSON.parse(resp["response"]["credential_options"])
    } catch (err) {
        return console.error("Error when getting request options from server:", err)
    }

    // convert certain members of the PublicKeyCredentialRequestOptions into
    // byte arrays as expected by the spec.
    const transformedCredentialRequestOptions = transformCredentialRequestOptions(
        credentialRequestOptionsFromServer)

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion
    try {
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        })
    } catch (err) {
        return console.error("Error when creating credential:", err)
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    const transformedAssertionForServer = transformAssertionForServer(assertion)

    // post the assertion to the server for verification.
    try {
        const resp = await postAssertionToServer(
          formData.get('response_url'), csrf_token,
          transformedAssertionForServer);
        if (display_errors(resp["response"], "wan-error")) {
          return
        }
        if ("post_login_url" in resp["response"]) {
          window.location.assign(resp["response"]["post_login_url"])
        }
    } catch (err) {
        return console.error("Error when validating assertion on server:", err)
    }

    //window.location.reload();
};

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData
 */
const getCredentialRequestOptionsFromServer = async (url, formData) => {
    return await fetch_json(
        url,
        {
            method: "POST",
            body: formData,
            headers: {
              "Accept": "application/json"
            },
        }
    );
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};



/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);
    const assertionClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        response: {
          authenticatorData: b64RawEnc(authData),
          clientDataJSON: b64RawEnc(clientDataJSON),
          signature: b64RawEnc(sig) },
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };
};

/**
 * Post the assertion to the server for validation and logging the user in.
 * @param {Object} assertionDataForServer
 */
const postAssertionToServer = async (url, csrf_token, assertionDataForServer) => {
    assertionDataForServer["csrf_token"] = csrf_token

    return await fetch_json(
        url, {
        method: "POST",
        body: JSON.stringify(assertionDataForServer),
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
    });
}


document.addEventListener("DOMContentLoaded", e => {
  const reg = document.querySelector('#wan_register')
  if (reg) {
    reg.addEventListener('click', didClickRegister);
  }
  const signin = document.querySelector('#wan_signin')
  if (signin) {
    signin.addEventListener('click', didClickLogin);
  }
});
