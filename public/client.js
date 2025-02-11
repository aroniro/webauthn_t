/*
 * @license
 * Copyright 2023 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
export const $ = document.querySelector.bind(document);

export async function _fetch(path, payload = '') {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest',
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: headers,
    body: payload,
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw new Error(result.error);
  }
};

export const base64url = {
  encode: function(buffer) {
    const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  },
  decode: function(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binStr = window.atob(base64);
    const bin = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bin[i] = binStr.charCodeAt(i);
    }
    return bin.buffer;
  }
}

class Loading {
  constructor() {
    this.progress = $('#progress');
  }
  start() {
    this.progress.indeterminate = true;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = true);
    }
  }
  stop() {
    this.progress.indeterminate = false;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = false);
    }
  }
}

export const loading = new Loading();

// TODO: Add an ability to create a passkey: Create the registerCredential() function.

function CM_base64url_encode(buffer) {
    return btoa(Array.from(new Uint8Array(buffer), function (b)
    { return String.fromCharCode(b); }).join(''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+${'$'}/, '');
}

// function base64ToUint8Array(base64) {
//     const binaryString = atob(base64);
//     const bytes = new Uint8Array(binaryString.length);
//     for (let i = 0; i < binaryString.length; i++) {
//         bytes[i] = binaryString.charCodeAt(i);
//     }
//     return bytes;
// }

function base64ToUint8Array(base64) {
    // ✅ URL-safe Base64를 일반 Base64로 변환
    base64 = base64.replace(/-/g, "+").replace(/_/g, "/");

    // ✅ 패딩(`=`) 추가하여 4의 배수 길이로 맞추기
    while (base64.length % 4 !== 0) {
        base64 += "=";
    }

    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function requestPasskeyRegistration(options) {
    return new Promise((resolve, reject) => {
        if (!window.webkit || !window.webkit.messageHandlers.webauthn) {
            return reject("❌ WebAuthn 네이티브 브릿지 지원되지 않음.");
        }

        // ✅ 유니크한 요청 ID 생성 (네이티브에서 응답할 때 사용)
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // ✅ 네이티브 응답을 받을 핸들러 등록
        window.passkeyResponseHandlers = window.passkeyResponseHandlers || {};
        window.passkeyResponseHandlers[requestId] = (response) => {
            delete window.passkeyResponseHandlers[requestId];
            if (response.success) {
                resolve(response.data);
            } else {
                reject(response.error);
            }
        };
      
        const decodedBytes = base64ToUint8Array(options.challenge);
        console.log("✅ Base64 디코딩 결과 (Uint8Array):", decodedBytes);

        // 2️⃣ 다시 Base64로 변환
        const base64Challenge = bufferToBase64(decodedBytes);

        // ✅ 네이티브로 Passkey 등록 요청
        window.webkit.messageHandlers.webauthn.postMessage({
            type: "register",
            username: options.user.name,
            challenge: base64Challenge,
            requestId: requestId // 요청 ID 전달
        });
    });
}

function requestPasskeyAuthentication(options) {
    return new Promise((resolve, reject) => {
        if (!window.webkit || !window.webkit.messageHandlers.webauthn) {
            return reject("❌ WebAuthn 네이티브 브릿지 지원되지 않음.");
        }

        // ✅ requestId 생성
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // ✅ 응답을 받을 핸들러 등록
        window.passkeyResponseHandlers = window.passkeyResponseHandlers || {};
        window.passkeyResponseHandlers[requestId] = (response) => {
            delete window.passkeyResponseHandlers[requestId];
            if (response.success) {
                resolve(response.data);
            } else {
                reject(response.error);
            }
        };

        // ✅ 네이티브로 Passkey 인증 요청 전송
        window.webkit.messageHandlers.webauthn.postMessage({
            type: "authenticate",
            challenge: options.challenge,
            requestId: requestId // 요청 ID 전달
        });
    });
}


export async function registerCredential() {

  // TODO: Add an ability to create a passkey: Obtain the challenge and other options from the server endpoint.

  const options = await _fetch('/auth/registerRequest');

  // TODO: Add an ability to create a passkey: Create a credential.

  // Base64URL decode some values.
  
  
  let cred;
  
//   if(navigator.userAgent.includes("iPhone")){
//     // options.challenge = arrayBufferToUint8Array(options.challenge)
//     // options.user.id = arrayBufferToUint8Array(options.user.id)
//     // console.log("changed");
//     // console.log(options);
// //     delete options.authenticatorSelection;
// //     delete options.extensions;
// //     delete options.attestation;  // 'none'이 기본값이므로 제거 가능
// //     delete options.excludeCredentials;  // 빈 배열이면 제거 가능
// //     delete options.timeout;  // 브라우저 기본값 사용
// //     console.log("changed");
// //     console.log(options);
    
// //     options.pubKeyCredParams = [
// //         { alg: -7, type: "public-key" }  // ES256만 남기기
// //     ];
//     cred = await requestPasskeyRegistration(options);
    
//     console.log(cred)
    
//     if(!cred){
//       console.log("cred null");
//       return;
//     }
    
//     const credential = {};
//     credential.id = cred.id;
//     credential.rawId = cred.id; // Pass a Base64URL encoded ID string.
//     credential.type = cred.type;

//     // The authenticatorAttachment string in the PublicKeyCredential object is a new addition in WebAuthn L3.
//     if (cred.authenticatorAttachment) {
//       credential.authenticatorAttachment = cred.authenticatorAttachment;
//     }

//     // Base64URL encode some values.
//     // const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
//     // const attestationObject = base64url.encode(cred.response.attestationObject);

//     // Obtain transports.
//     const transports = [];

//     credential.response = {
//       clientDataJSON: cred.response.clientDataJSON,
//       attestationObject: cred.response.attestationObject,
//       transports
//     };

//     return await _fetch('/auth/registerResponse', credential);
    
    
//   }else{
    options.user.id = base64url.decode(options.user.id);
    options.challenge = base64url.decode(options.challenge);

    if (options.excludeCredentials) {
      for (let cred of options.excludeCredentials) {
        cred.id = base64url.decode(cred.id);
      }
    }

    // Use platform authenticator and discoverable credential.
    options.authenticatorSelection = {
      authenticatorAttachment: 'platform',
      requireResidentKey: true
    }

    console.log("Current Host:", window.location.hostname);
    console.log(options);
    
    cred = await navigator.credentials.create({
      publicKey: options,
    });
    
    if(!cred){
      console.log("cred null");
      return;
    }
    
    const credential = {};
    credential.id = cred.id;
    credential.rawId = cred.id; // Pass a Base64URL encoded ID string.
    credential.type = cred.type;

    // The authenticatorAttachment string in the PublicKeyCredential object is a new addition in WebAuthn L3.
    if (cred.authenticatorAttachment) {
      credential.authenticatorAttachment = cred.authenticatorAttachment;
    }

    // Base64URL encode some values.
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);

    // Obtain transports.
    const transports = cred.response.getTransports ? cred.response.getTransports() : [];

    credential.response = {
      clientDataJSON,
      attestationObject,
      transports
    };

    return await _fetch('/auth/registerResponse', credential);
  // }

  // Invoke the WebAuthn create() method.
  // const cred = await navigator.credentials.create({
  //   publicKey: options,
  // });
  

  // TODO: Add an ability to create a passkey: Register the credential to the server endpoint.

  
};

// TODO: Add an ability to authenticate with a passkey: Create the authenticate() function.

export async function authenticate() {

  // TODO: Add an ability to authenticate with a passkey: Obtain the challenge and other options from the server endpoint.

  const options = await _fetch('/auth/signinRequest');

  // TODO: Add an ability to authenticate with a passkey: Locally verify the user and get a credential.
  
  let cred;
//   if(navigator.userAgent.includes("iPhone")){
//     cred = await requestPasskeyAuthentication(options);
    
//     const credential = {};
//     credential.id = cred.id;
//     credential.rawId = cred.id; // Pass a Base64URL encoded ID string.
//     credential.type = cred.type;
    
//     credential.response = {
//       clientDataJSON: cred.response.clientDataJSON,
//       authenticatorData: cred.response.authenticatorData,
//       signature: cred.response.signature,
//       userHandle: cred.response.userHandle,
//     };

//     return await _fetch(`/auth/signinResponse`, credential);
//   }else{
    // Base64URL decode the challenge.
    options.challenge = base64url.decode(options.challenge);

    // An empty allowCredentials array invokes an account selector by discoverable credentials.
    options.allowCredentials = [];

    // Invoke the WebAuthn get() method.
    cred = await navigator.credentials.get({
      publicKey: options,
      // Request a conditional UI
      mediation: 'conditional'
    });

    // TODO: Add an ability to authenticate with a passkey: Verify the credential.

    const credential = {};
    credential.id = cred.id;
    credential.rawId = cred.id; // Pass a Base64URL encoded ID string.
    credential.type = cred.type;

    // Base64URL encode some values.
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };

    return await _fetch(`/auth/signinResponse`, credential);
  // }
};

export async function updateCredential(credId, newName) {
  return _fetch(`/auth/renameKey`, { credId, newName });
}

export async function unregisterCredential(credId) {
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};
