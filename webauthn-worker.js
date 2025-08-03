// webauthn-worker.js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    if (request.method === 'OPTIONS') {
      return handleCors();
    }

    if (url.pathname === '/generate-registration-options') {
      return handleGenerateRegistrationOptions(request, env);
    }
    
    if (url.pathname === '/verify-registration') {
      return handleVerifyRegistration(request, env);
    }
    
    if (url.pathname === '/generate-authentication-options') {
      return handleGenerateAuthenticationOptions(request, env);
    }
    
    if (url.pathname === '/verify-authentication') {
      return handleVerifyAuthentication(request, env);
    }

    return new Response('Not Found', { status: 404 });
  }
};

function handleCors() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
}

function setCORSHeaders(response) {
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return response;
}

async function handleGenerateRegistrationOptions(request, env) {
  const { userId, username, displayName } = await request.json();
  
  // Generate a unique challenge as ArrayBuffer
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  
  const options = {
    rp: {
      name: env.RP_NAME || 'KM-RS',
      id: env.RP_ID || 'fwzj3p7v-5173.use.devtunnels.ms'
    },
    user: {
      id: stringToBuffer(userId),
      name: username,
      displayName: displayName
    },
    challenge: Array.from(challenge),
    pubKeyCredParams: [
      { alg: -7, type: "public-key" }, // ES256
      { alg: -257, type: "public-key" } // RS256
    ],
    timeout: 60000,
    attestation: "none", // Changed to none for better compatibility
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: false,
      userVerification: "preferred"
    }
  };

  const response = new Response(JSON.stringify({
    options,
    challenge: Array.from(challenge)
  }), {
    headers: { 'Content-Type': 'application/json' }
  });

  return setCORSHeaders(response);
}

async function handleVerifyRegistration(request, env) {
  const { credential, challenge } = await request.json();
  
  try {
    if (!credential || !credential.id || !credential.response) {
      throw new Error('Invalid registration data');
    }

    const credentialId = credential.id;
    const publicKey = credential.response.publicKey;
    
    if (!credentialId || !publicKey) {
      throw new Error('Missing credential data');
    }

    return setCORSHeaders(new Response(JSON.stringify({ 
      success: true, 
      credentialId,
      publicKey
    }), {
      headers: { 'Content-Type': 'application/json' }
    }));
  } catch (error) {
    return setCORSHeaders(new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    }));
  }
}

async function handleGenerateAuthenticationOptions(request, env) {
  const { credentialIds } = await request.json();
  
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  
  // Filter out invalid credential IDs
  const validCredentialIds = (credentialIds || []).filter((id) => id && id.length > 0);
  
  const options = {
    challenge: Array.from(challenge),
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials: validCredentialIds.map((id) => ({
      id: Array.from(stringToBuffer(id)),
      type: "public-key",
      transports: ["internal", "usb", "nfc", "ble"]
    }))
  };

  const response = new Response(JSON.stringify({
    options,
    challenge: Array.from(challenge)
  }), {
    headers: { 'Content-Type': 'application/json' }
  });

  return setCORSHeaders(response);
}

async function handleVerifyAuthentication(request, env) {
  const { credential, challenge } = await request.json();
  
  try {
    if (!credential || !credential.id || !credential.response) {
      throw new Error('Invalid authentication data');
    }

    const credentialId = credential.id;
    
    if (!credentialId) {
      throw new Error('Missing credential ID');
    }

    return setCORSHeaders(new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    }));
  } catch (error) {
    return setCORSHeaders(new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    }));
  }
}

// Helper functions
function stringToBuffer(str) {
  return Uint8Array.from(str, c => c.charCodeAt(0));
}