/**
 * Thanks to duo-labs/py_webauthn - this is their OLD flask demo.
 * Modified accordingly...
 * This code should be considered to be licensed:
 * Copyright (c) 2017 Duo Security, Inc. All rights reserved.
 * with the BSD 3-Clause "New" or "Revised" License.
 * Further changes:
 *  :copyright: (c) 2021-2021 by J. Christopher Wagner (jwag).
 *  :license: MIT, see LICENSE for more details.
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
    if (body.fail) {
      // Convert exception to our JSON API response.
      return {
        response: {
          error: body.fail
        }
      }
    }
    return body;
}

/*
 * Flask-Security API JSON response has:
 * ["response"]["error"] = str OR
 * ["response"]["errors"]["<field_name>"] = list of str
 *
 * Given a response - look for errors and insert them into an element
 *  - and return True if there were some.
 */
function display_errors(response, id) {
  if (!("error" in response) && !("errors" in response))
    return false

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

function clear_errors(id) {
  const error_element = document.getElementById(id)
  if (error_element)
    error_element.innerHTML = ''
}

/**
 * REGISTRATION FUNCTIONS
 */

/*
 * handleRegister - given the return from server of credential_options,
 * parse those and pass to browser to create new credential, and transform
 * that new credential for passing/storing to the server.
 */
async function handleRegister(credential_options, error_elmid) {
  const credentialCreateOptionsFromServer = JSON.parse(credential_options);

  // convert certain members of the PublicKeyCredentialCreateOptions into
  // byte arrays as expected by the spec.
  const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer)

  // request the authenticator(s) to create a new credential keypair.
  let credential;
  clear_errors(error_elmid)
  try {
      credential = await navigator.credentials.create({
          publicKey: publicKeyCredentialCreateOptions
      })
      // we now have a new credential! We now need to encode the byte arrays
      // in the credential into strings, for posting to our server.
      return JSON.stringify(transformNewAssertionForServer(credential))
  } catch (err) {
    const err_msg = `Error creating credential: ${err}`
    display_errors({error: err_msg}, error_elmid)
  }
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
            .replace(/_/g, "/")
            .replace(/-/g, "+")
            ),
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/_/g, "/")
            .replace(/-/g, "+")
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
        extensions: JSON.stringify(registrationClientExtensions),
        transports: newAssertion.response.getTransports(),
    };
}



/**
 * AUTHENTICATION FUNCTIONS
 */


async function handleSignin(response, error_elmid) {
  const credentialRequestOptionsFromServer = JSON.parse(response)
  // convert certain members of the PublicKeyCredentialRequestOptions into
  // byte arrays as expected by the spec.
  const transformedCredentialRequestOptions = transformCredentialRequestOptions(
      credentialRequestOptionsFromServer)

  // request the authenticator to create an assertion signature using the
  // credential private key
  let assertion
  clear_errors(error_elmid)
  try {
    assertion = await navigator.credentials.get({
        publicKey: transformedCredentialRequestOptions,
    })
    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    return JSON.stringify(transformAssertionForServer(assertion))
  } catch (err) {
    const err_msg = `Error when creating credential: ${err}`
    display_errors({error: err_msg}, error_elmid)
  }
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/_/g, "/").replace(/-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/_/g, "/").replace(/-/g, "+");
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
