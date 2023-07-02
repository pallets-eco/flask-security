/**
 * Thanks to duo-labs/py_webauthn - this is their OLD flask demo.
 * Modified accordingly...
 * This code should be considered to be licensed:
 * Copyright (c) 2017 Duo Security, Inc. All rights reserved.
 * with the BSD 3-Clause "New" or "Revised" License.
 * Further changes:
 *  :copyright: (c) 2021-2022 by J. Christopher Wagner (jwag).
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

function encode(attr) {
  return Uint8Array.from(
    atob(attr.replace(/_/g, "/").replace(/-/g, "+")),
    c => c.charCodeAt(0));
}

/**
 * REGISTRATION FUNCTIONS
 */

/*
 * handleRegister - given the return from server of credential_options,
 * parse those and pass to browser to create new credential, and transform
 * that new credential for passing/storing to the server.
 */
async function handleRegister(credential_options) {
  const credentialCreateOptionsFromServer = JSON.parse(credential_options)

  // convert certain members of the PublicKeyCredentialCreateOptions into
  // byte arrays as expected by the spec.
  const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer)

  // request the authenticator(s) to create a new credential keypair.
  let credential, error_msg
  try {
      credential = await navigator.credentials.create({
          publicKey: publicKeyCredentialCreateOptions
      })
      // we now have a new credential! We now need to encode the byte arrays
      // in the credential into strings, for posting to our server.
      credential = JSON.stringify(transformNewAssertionForServer(credential))
  } catch (err) {
    error_msg = `Error when creating credential: ${err}`
  }
  return {"credential": credential, "error_msg": error_msg}
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user, excludeCredentials} = credentialCreateOptionsFromServer
    user.id = encode(credentialCreateOptionsFromServer.user.id)
    challenge = encode(credentialCreateOptionsFromServer.challenge)

    excludeCredentials = excludeCredentials.map(credentialDescriptor => {
      let {id} = credentialDescriptor;
      id = encode(id)
      return Object.assign({}, credentialDescriptor, {id})
    })

    const transformedCredentialCreateOptions = Object.assign(
      {},
      credentialCreateOptionsFromServer,
      {challenge, user, excludeCredentials}
    )

    return transformedCredentialCreateOptions
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

    // Not all browsers support getTransports() (e.g. Firefox)
    let transports = null
    if ("getTransports" in newAssertion.response) {
      transports = newAssertion.response.getTransports()
    }

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        response: {"attestationObject": b64enc(attObj), "clientDataJSON": b64enc(clientDataJSON), "transports": transports},
        extensions: JSON.stringify(registrationClientExtensions),
    }
}



/**
 * AUTHENTICATION FUNCTIONS
 */


async function handleSignin(response) {
  const credentialRequestOptionsFromServer = JSON.parse(response)
  // convert certain members of the PublicKeyCredentialRequestOptions into
  // byte arrays as expected by the spec.
  const transformedCredentialRequestOptions = transformCredentialRequestOptions(
      credentialRequestOptionsFromServer)

  // request the authenticator to create an assertion signature using the
  // credential private key
  let assertion, credential, error_msg
  try {
    assertion = await navigator.credentials.get({
        publicKey: transformedCredentialRequestOptions,
    })
    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    credential = JSON.stringify(transformAssertionForServer(assertion))
  } catch (err) {
    error_msg = `Error when retrieving credential: ${err}`
  }
  return {"credential": credential, "error_msg": error_msg}
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer

    challenge = encode(challenge)
    allowCredentials = allowCredentials.map(credentialDescriptor => {
      let {id} = credentialDescriptor
      id = encode(id)
      return Object.assign({}, credentialDescriptor, {id})
    })

    const transformedCredentialRequestOptions = Object.assign(
      {},
      credentialRequestOptionsFromServer,
      {challenge, allowCredentials}
    )

    return transformedCredentialRequestOptions
}



/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON)
    const rawId = new Uint8Array(newAssertion.rawId)
    const sig = new Uint8Array(newAssertion.response.signature)
    const userHandle = new Uint8Array(newAssertion.response.userHandle)
    const assertionClientExtensions = newAssertion.getClientExtensionResults()

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        response: {
          authenticatorData: b64RawEnc(authData),
          clientDataJSON: b64RawEnc(clientDataJSON),
          signature: b64RawEnc(sig),
          userHandle: b64RawEnc(userHandle)
        },
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };
};
