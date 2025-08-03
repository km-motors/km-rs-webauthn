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

    // Generate a unique challenge
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const challengeBase64 = arrayBufferToBase64(challenge);

    // Store challenge temporarily (in production, use KV or database)
    // For demo purposes, we'll return it directly
    const options = {
        rp: {
            name: env.RP_NAME || 'Your App',
            id: env.RP_ID
        },
        user: {
            id: userId,
            name: username,
            displayName: displayName
        },
        challenge: challengeBase64,
        pubKeyCredParams: [
            { alg: -7, type: "public-key" }, // ES256
            { alg: -257, type: "public-key" } // RS256
        ],
        timeout: 60000,
        attestation: " indirect",
        excludeCredentials: [],
        authenticatorSelection: {
            authenticatorAttachment: "platform",
            requireResidentKey: false,
            userVerification: "preferred"
        }
    };

    const response = new Response(JSON.stringify({
        options,
        challenge: challengeBase64
    }), {
        headers: { 'Content-Type': 'application/json' }
    });

    return setCORSHeaders(response);
}

async function handleVerifyRegistration(request, env) {
    const { credential, challenge } = await request.json();

    try {
        // Basic validation - in production, use a proper WebAuthn library
        const isValid = validateRegistrationResponse(credential, challenge);

        if (isValid) {
            return setCORSHeaders(new Response(JSON.stringify({
                success: true,
                credentialId: credential.id,
                publicKey: credential.response.publicKey
            }), {
                headers: { 'Content-Type': 'application/json' }
            }));
        } else {
            return setCORSHeaders(new Response(JSON.stringify({ success: false }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            }));
        }
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
    const challengeBase64 = arrayBufferToBase64(challenge);

    const options = {
        challenge: challengeBase64,
        timeout: 60000,
        userVerification: "preferred",
        allowCredentials: credentialIds.map(id => ({
            id,
            type: "public-key",
            transports: ["internal", "usb", "nfc", "ble"]
        }))
    };

    const response = new Response(JSON.stringify({
        options,
        challenge: challengeBase64
    }), {
        headers: { 'Content-Type': 'application/json' }
    });

    return setCORSHeaders(response);
}

async function handleVerifyAuthentication(request, env) {
    const { credential, challenge } = await request.json();

    try {
        // Basic validation - in production, use a proper WebAuthn library
        const isValid = validateAuthenticationResponse(credential, challenge);

        if (isValid) {
            return setCORSHeaders(new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            }));
        } else {
            return setCORSHeaders(new Response(JSON.stringify({ success: false }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            }));
        }
    } catch (error) {
        return setCORSHeaders(new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        }));
    }
}

// Helper functions
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function validateRegistrationResponse(credential, expectedChallenge) {
    // Simplified validation - implement proper validation in production
    return credential && credential.id && credential.response && expectedChallenge;
}

function validateAuthenticationResponse(credential, expectedChallenge) {
    // Simplified validation - implement proper validation in production
    return credential && credential.id && credential.response && expectedChallenge;
}