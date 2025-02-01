from flask import Flask, request, jsonify, redirect, url_for, render_template_string, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import time
import os
import base64
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from authlib.jose import jwt, JsonWebKey
from substrateinterface import Keypair
from flask_cors import CORS
import urllib.parse

app = Flask(__name__)
# Enable CORS for all routes
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:8008", "http://localhost:5000"],
        "supports_credentials": True
    }
})
app.secret_key = 'your-secret-key'  # Use a secure secret key in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_DOMAIN'] = 'localhost'  # Match your domain

def verify_signature_basic(address, signature, payload):
    try:
        keypair = Keypair(ss58_address=address)
        return keypair.verify(data=payload.encode("utf-8"), signature=signature)
    except Exception:
        return False

# Generate RSA key pair for JWT signing
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Convert to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Create JWK from public key
jwk = JsonWebKey.import_key(public_pem, {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': '1'})
public_jwk = jwk.as_dict()

# OIDC Configuration
ISSUER = "http://localhost:5000"
CLIENT_ID = "123456"
CLIENT_SECRET = "2c0c5502258bec795333828e3d7548b8"

# In-memory storage for challenge messages
auth_challenges = {}

def get_redirect_uri(redirect_uri):
    # Replace internal docker URLs with localhost for browser redirects
    if "custom-auth-provider:5000" in redirect_uri:
        return redirect_uri.replace("custom-auth-provider:5000", "localhost:5000")
    if "matrix-synapse:8008" in redirect_uri:
        return redirect_uri.replace("matrix-synapse:8008", "localhost:8008")
    return redirect_uri

@app.route('/')
def index():
    if 'wallet_address' in session:
        return f'Logged in as {session["wallet_address"]} <br><a href="/logout">Logout</a>'
    return 'You are not logged in <br><a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login with Polkadot</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        button {
            background-color: #E6007A;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px 0;
        }
        button:hover {
            background-color: #C4006B;
        }
        select {
            padding: 8px;
            margin: 10px 0;
            width: 100%;
            max-width: 400px;
        }
        #account-section {
            margin-top: 20px;
        }
    </style>
    <script type="module">
        import { web3Accounts, web3Enable, web3FromSource } from 'https://cdn.jsdelivr.net/npm/@polkadot/extension-dapp/+esm';
        import { stringToHex } from 'https://cdn.jsdelivr.net/npm/@polkadot/util/+esm';

        let allAccounts = [];
        let selectedAccount = null;

        async function enableWallet() {
            const allInjected = await web3Enable('Matrix Auth App');
            if (!allInjected.length) {
                alert("No extension found. Please install Polkadot.js extension.");
                return;
            }

            allAccounts = await web3Accounts();
            if (!allAccounts.length) {
                alert("No accounts found. Please add an account in the extension.");
                return;
            }

            const accountsDropdown = document.getElementById('accounts');
            accountsDropdown.innerHTML = ''; // Clear previous options
            allAccounts.forEach(account => {
                const option = document.createElement('option');
                option.value = account.address;
                option.textContent = `${account.meta.name} (${account.address})`;
                accountsDropdown.appendChild(option);
            });
            document.getElementById('account-section').style.display = 'block';
        }

        async function selectAccount() {
            selectedAccount = allAccounts.find(acc => acc.address === document.getElementById('accounts').value);
            document.getElementById('selected-account').textContent = `Selected Account: ${selectedAccount.address}`;
            
            // Get challenge from server
            const response = await fetch('/get_challenge', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    address: selectedAccount.address
                })
            });
            
            if (!response.ok) {
                alert('Failed to get challenge from server');
                return;
            }
            
            const { challenge } = await response.json();
            
            // Sign the challenge
            const injector = await web3FromSource(selectedAccount.meta.source);
            const signRaw = injector?.signer?.signRaw;
            
            if (!!signRaw) {
                try {
                    const { signature } = await signRaw({
                        address: selectedAccount.address,
                        data: stringToHex(challenge),
                        type: 'bytes'
                    });
                    
                    // Verify signature with server
                    const verifyResponse = await fetch('/verify_signature', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            address: selectedAccount.address,
                            challenge: challenge,
                            signature: signature
                        })
                    });
                    
                    if (verifyResponse.ok) {
                        const { redirect_url } = await verifyResponse.json();
                        window.location.href = redirect_url;
                    } else {
                        alert('Signature verification failed');
                    }
                } catch (error) {
                    alert('Failed to sign message: ' + error.message);
                }
            } else {
                alert("Signing not available.");
            }
        }

        // Attach functions to window object
        window.enableWallet = enableWallet;
        window.selectAccount = selectAccount;
    </script>
</head>
<body>
    <h1>Login with Polkadot</h1>
    <p>Connect your Polkadot wallet to authenticate:</p>
    <button onclick="enableWallet()">Connect Wallet</button>
    <div id="account-section" style="display: none;">
        <h2>Select an Account</h2>
        <select id="accounts" onchange="selectAccount()"></select>
        <p id="selected-account"></p>
    </div>
</body>
</html>
        ''')

@app.route('/get_challenge', methods=['POST'])
def get_challenge():
    data = request.get_json()
    address = data.get('address')
    if not address:
        return jsonify({'error': 'Address is required'}), 400
    
    # Generate a random challenge message
    challenge = secrets.token_hex(32)
    auth_challenges[address] = challenge
    
    return jsonify({'challenge': challenge})

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    data = request.get_json()
    address = data.get('address')
    challenge = data.get('challenge')
    signature = data.get('signature')
    
    if not all([address, challenge, signature]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Verify that the challenge matches
    stored_challenge = auth_challenges.get(address)
    if not stored_challenge or stored_challenge != challenge:
        return jsonify({'error': 'Invalid challenge'}), 400
    
    try:
        # Verify the signature using substrate-interface
        is_valid = verify_signature_basic(
            address,
            signature,
            challenge,
        )
        
        if is_valid:
            # Clear the challenge
            del auth_challenges[address]
            # Set the session
            session['wallet_address'] = address
            session.modified = True
            
            # If we have OAuth params, continue the OAuth flow
            if 'oauth_params' in session:
                params = session['oauth_params']
                code_claims = {
                    "sub": address,
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 600,  # Code expires in 10 minutes
                    "iss": ISSUER,
                    "aud": params['client_id'],
                    "nonce": params.get('nonce'),
                    "auth_time": int(time.time())
                }
                
                # Sign the claims with our private key
                code = jwt.encode({'alg': 'RS256', 'kid': '1'}, code_claims, private_pem)
                
                # Store the code claims for later token exchange
                session['code_claims'] = code_claims
                session.modified = True
                
                # Get the redirect URI and encode the code properly
                redirect_uri = get_redirect_uri(params['redirect_uri'])
                encoded_code = urllib.parse.quote(code)
                
                # Return success with redirect URL
                response = jsonify({
                    'success': True,
                    'redirect_url': f"{redirect_uri}?code={encoded_code}&state={params.get('state', '')}"
                })
                return response
            
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Invalid signature'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/auth', methods=['GET'])
def auth():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type', 'code')
    scope = request.args.get('scope', '')
    state = request.args.get('state')
    nonce = request.args.get('nonce')

    # Store OAuth parameters in session
    session['oauth_params'] = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': scope,
        'state': state,
        'nonce': nonce
    }
    session.modified = True

    # Validate client_id
    if client_id != CLIENT_ID:
        return 'Invalid client_id', 401

    if 'wallet_address' in session:
        # User is already logged in, generate authorization code
        code_claims = {
            "sub": session['wallet_address'],
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,  # Code expires in 10 minutes
            "iss": ISSUER,
            "aud": client_id,
            "nonce": nonce,
            "auth_time": int(time.time())
        }
        
        # Sign the claims with our private key
        code = jwt.encode({'alg': 'RS256', 'kid': '1'}, code_claims, private_pem)
        
        # Store the code claims for later token exchange
        session['code_claims'] = code_claims
        session.modified = True
        
        # Redirect back to the client with the code
        redirect_uri = get_redirect_uri(redirect_uri)
        response = make_response(redirect(f"{redirect_uri}?code={code}&state={state}"))
        return response
    
    # User needs to log in
    return render_template_string('''
        <h1>Login</h1>
        <a href="/login">Login with Polkadot</a>
    ''')

@app.route('/logout')
def logout():
    session.pop('wallet_address', None)
    return redirect(url_for('index'))

@app.route('/.well-known/openid-configuration')
def openid_configuration():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/auth",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "claims_supported": ["sub", "name", "email", "preferred_username"]
    })

@app.route('/.well-known/jwks.json')
def jwks():
    return jsonify({
        "keys": [public_jwk]
    })

@app.route('/token', methods=['POST'])
def token():
    # Verify client credentials
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Basic '):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            client_id, client_secret = decoded.split(':')
            if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
                return jsonify({'error': 'invalid_client'}), 401
        except Exception:
            return jsonify({'error': 'invalid_client'}), 401
    else:
        form_client_id = request.form.get('client_id')
        form_client_secret = request.form.get('client_secret')
        if form_client_id != CLIENT_ID or form_client_secret != CLIENT_SECRET:
            return jsonify({'error': 'invalid_client'}), 401

    if request.form.get('grant_type') == 'authorization_code':
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        
        if not code or not redirect_uri:
            return jsonify({'error': 'invalid_request'}), 400

        try:
            # Verify the JWT code
            claims = jwt.decode(code, public_pem)
            wallet_address = claims['sub']
            
            # Generate tokens
            access_claims = {
                "sub": wallet_address,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "scope": "openid profile email"
            }
            
            id_claims = {
                "sub": wallet_address,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "nonce": claims.get('nonce'),
                "name": wallet_address,
                "preferred_username": wallet_address,
                "email": f"{wallet_address}@example.com"
            }

            header = {'alg': 'RS256', 'kid': '1'}
            
            return jsonify({
                'access_token': jwt.encode(header, access_claims, private_pem).decode('utf-8'),
                'token_type': 'Bearer',
                'id_token': jwt.encode(header, id_claims, private_pem).decode('utf-8'),
                'expires_in': 3600,
                'scope': 'openid profile email'
            })
        except Exception as e:
            print(f"Token error: {str(e)}")
            return jsonify({'error': 'invalid_grant'}), 400
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

@app.route('/userinfo')
def userinfo():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return 'Unauthorized', 401
    
    token = auth_header.split(' ')[1]
    try:
        claims = jwt.decode(token, public_pem)
        wallet_address = claims['sub']
        return jsonify({
            "sub": wallet_address,
            "name": wallet_address,
            "preferred_username": wallet_address,
            "email": f"{wallet_address}@example.com"
        })
    except Exception as e:
        print(f"Userinfo error: {str(e)}")
        return 'Invalid token', 401

@app.after_request
def after_request(response):
    # Allow requests from Matrix server
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8008')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)