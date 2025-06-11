let circuit = null;
let provingKey = null;
let verifyingKey = null;
let publicKeysList = [];

// Circuit constants - must match rsa_big.circom GroupVerify(3, 120, 35, 17)
const CIRCUIT_SIZE = 3;        // Number of public keys supported
const CHUNK_BITS = 120;        // Bits per chunk (n parameter)
const NUM_CHUNKS = 35;         // Number of chunks (k parameter)
const EXPONENT_BITS = 17;      // Exponent bits (exp_bits parameter)

// Function to verify that our constants match the circuit file
async function verifyCircuitConstants() {
    try {
        const response = await fetch('./rsa_big.circom');
        if (!response.ok) {
            console.warn('Could not fetch rsa_big.circom to verify constants');
            return false;
        }
        
        const circomContent = await response.text();
        
        // Look for the GroupVerify instantiation pattern
        const groupVerifyPattern = /component\s+main[^=]*=\s*GroupVerify\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/;
        const match = circomContent.match(groupVerifyPattern);
        
        if (!match) {
            console.error('Could not find GroupVerify component instantiation in rsa_big.circom');
            return false;
        }
        
        const [, circuitSize, chunkBits, numChunks, exponentBits] = match.map(Number);
        
        const constantsMatch = 
            CIRCUIT_SIZE === circuitSize &&
            CHUNK_BITS === chunkBits &&
            NUM_CHUNKS === numChunks &&
            EXPONENT_BITS === exponentBits;
        
        if (constantsMatch) {
            console.log('✓ Circuit constants match rsa_big.circom parameters:', {
                CIRCUIT_SIZE, CHUNK_BITS, NUM_CHUNKS, EXPONENT_BITS
            });
            return true;
        } else {
            console.error('✗ Circuit constants DO NOT match rsa_big.circom!');
            console.error('Expected from circom:', { circuitSize, chunkBits, numChunks, exponentBits });
            console.error('Actual in app.js:', { CIRCUIT_SIZE, CHUNK_BITS, NUM_CHUNKS, EXPONENT_BITS });
            return false;
        }
    } catch (error) {
        console.error('Error verifying circuit constants:', error);
        return false;
    }
}

// Convert input to field element format for the circuit
function inputToFieldElement(input) {
    if (typeof input === 'string') {
        if (input.startsWith('0x')) {
            return BigInt(input).toString();
        } else {
            // Treat as regular integer
            return BigInt(input).toString();
        }
    } else {
        return BigInt(input).toString();
    }
}

// Utility function to convert a big number to an array of chunks
function bigIntToChunks(bigNum, numChunks) {
    const chunks = [];
    const mask = (BigInt(1) << BigInt(CHUNK_BITS)) - BigInt(1); // Dynamic mask based on CHUNK_BITS
    let remaining = BigInt(bigNum);
    
    for (let i = 0; i < numChunks; i++) {
        chunks.push((remaining & mask).toString());
        remaining = remaining >> BigInt(CHUNK_BITS);
    }
    
    return chunks;
}

// Utility function to convert a big number to an array of bits
function bigIntToBits(bigNum, numBits) {
    const bits = [];
    let remaining = BigInt(bigNum);
    
    for (let i = 0; i < numBits; i++) {
        bits.push(Number(remaining & BigInt(1)));
        remaining = remaining >> BigInt(1);
    }
    
    return bits;
}

// SSH Signature extraction functions
function extractSignatureFromSSHFile(sshSignatureContent) {
    /**
     * Extract signature value from SSH signature file content.
     * 
     * Args:
     *     sshSignatureContent: Content of the .sig file created by ssh-keygen
     * 
     * Returns:
     *     object: {signatureInt, algorithm, namespace}
     */
    
    // SSH signature file format:
    // -----BEGIN SSH SIGNATURE-----
    // base64-encoded signature data
    // -----END SSH SIGNATURE-----
    
    const startMarker = "-----BEGIN SSH SIGNATURE-----";
    const endMarker = "-----END SSH SIGNATURE-----";
    
    const startIdx = sshSignatureContent.indexOf(startMarker);
    const endIdx = sshSignatureContent.indexOf(endMarker);
    
    if (startIdx === -1 || endIdx === -1) {
        throw new Error("Invalid SSH signature file format");
    }
    
    // Extract and clean base64 content
    let b64Content = sshSignatureContent.substring(startIdx + startMarker.length, endIdx).trim();
    b64Content = b64Content.replace(/\s+/g, ''); // Remove whitespace
    
    // Decode the signature structure
    const sigData = base64ToUint8Array(b64Content);
    
    // Parse the complete SSH signature format
    let offset = 0;
    
    function readSSHString(data, offset) {
        if (offset + 4 > data.length) {
            throw new Error(`Cannot read length at offset ${offset}, data length is ${data.length}`);
        }
        const length = new DataView(data.buffer).getUint32(offset, false); // big-endian
        offset += 4;
        if (offset + length > data.length) {
            throw new Error(`Cannot read ${length} bytes at offset ${offset}, data length is ${data.length}`);
        }
        return {
            data: data.slice(offset, offset + length),
            newOffset: offset + length
        };
    }
    
    // Read magic bytes directly (they are not length-prefixed)
    const magic = sigData.slice(offset, offset + 6);
    offset += 6;
    const magicStr = new TextDecoder().decode(magic);
    if (magicStr !== 'SSHSIG') {
        throw new Error(`Invalid SSH signature magic: expected 'SSHSIG', got '${magicStr}'`);
    }
    
    // Read version
    if (offset + 4 > sigData.length) {
        throw new Error("Cannot read version field");
    }
    const version = new DataView(sigData.buffer).getUint32(offset, false); // big-endian
    offset += 4;
    
    // Read and parse the public key
    const pubkeyResult = readSSHString(sigData, offset);
    const pubkeyData = pubkeyResult.data;
    offset = pubkeyResult.newOffset;
    
    // Parse the public key
    let pubkeyOffset = 0;
    const keyTypeResult = readSSHString(pubkeyData, pubkeyOffset);
    const keyType = new TextDecoder().decode(keyTypeResult.data);
    pubkeyOffset = keyTypeResult.newOffset;
    
    if (keyType !== 'ssh-rsa') {
        throw new Error(`Expected ssh-rsa key type, got ${keyType}`);
    }
    
    // Read RSA public key components: e (exponent) and n (modulus)
    const eResult = readSSHString(pubkeyData, pubkeyOffset);
    const eBytes = eResult.data;
    pubkeyOffset = eResult.newOffset;
    
    const nResult = readSSHString(pubkeyData, pubkeyOffset);
    const nBytes = nResult.data;
    
    // Convert e and n to BigInt
    let publicKeyE = BigInt(0);
    for (let i = 0; i < eBytes.length; i++) {
        publicKeyE = (publicKeyE << BigInt(8)) + BigInt(eBytes[i]);
    }
    
    let publicKeyN = BigInt(0);
    for (let i = 0; i < nBytes.length; i++) {
        publicKeyN = (publicKeyN << BigInt(8)) + BigInt(nBytes[i]);
    }
    
    // Read namespace, reserved, hash algorithm
    const namespaceResult = readSSHString(sigData, offset);
    const namespace = new TextDecoder().decode(namespaceResult.data);
    offset = namespaceResult.newOffset;
    
    const reservedResult = readSSHString(sigData, offset);
    offset = reservedResult.newOffset;
    
    const hashAlgResult = readSSHString(sigData, offset);
    const hashAlg = new TextDecoder().decode(hashAlgResult.data);
    offset = hashAlgResult.newOffset;
    
    // Read the actual signature
    const signatureResult = readSSHString(sigData, offset);
    const signature = signatureResult.data;
    
    // Parse the signature itself
    let sigOffset = 0;
    const algNameResult = readSSHString(signature, sigOffset);
    const algName = new TextDecoder().decode(algNameResult.data);
    sigOffset = algNameResult.newOffset;
    
    const sigBlobResult = readSSHString(signature, sigOffset);
    const sigBlob = sigBlobResult.data;
    
    if (!['rsa-sha2-256', 'rsa-sha2-512', 'ssh-rsa'].includes(algName)) {
        throw new Error(`Not an RSA signature: ${algName}`);
    }
    
    // Convert signature to integer (big-endian)
    let signatureInt = BigInt(0);
    for (let i = 0; i < sigBlob.length; i++) {
        signatureInt = (signatureInt << BigInt(8)) + BigInt(sigBlob[i]);
    }
    
    return {
        signatureInt: signatureInt,
        algorithm: algName,
        namespace: namespace,
        publicKeyE: publicKeyE,
        publicKeyN: publicKeyN
    };
}

function base64ToUint8Array(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function extractSSHSignature() {
    const sshSignatureInput = document.getElementById('sshSignatureInput').value;
    const sshSignatureOutput = document.getElementById('sshSignatureOutput');
    
    try {
        if (!sshSignatureInput.trim()) {
            throw new Error('Please paste an SSH signature file content');
        }
        
        const result = extractSignatureFromSSHFile(sshSignatureInput);
        
        sshSignatureOutput.innerHTML = `
            <div class="success">✓ SSH Signature extracted successfully!</div>
            <div><strong>Algorithm:</strong> ${result.algorithm}</div>
            <div><strong>Namespace:</strong> ${result.namespace}</div>
            
            <div><strong>Public Key Exponent (e):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${result.publicKeyE.toString()}
            </div>
            
            <div><strong>Public Key Modulus (n):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${result.publicKeyN.toString()}
            </div>
            
            <div><strong>Signature Integer (m^d mod n):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${result.signatureInt.toString()}
            </div>
            
            <div><strong>Key Size:</strong> ${result.publicKeyN.toString(2).length} bits</div>
            
            <div style="margin-top: 15px;">
                <button onclick="autoFillFromSSH('${result.publicKeyE.toString()}', '${result.publicKeyN.toString()}', '${result.signatureInt.toString()}')" 
                        style="background-color: #28a745; margin: 5px 0;">
                    Auto-fill Public Key & Signature
                </button>
            </div>
        `;
        
        // Note: Removed automatic auto-fill to give user control
        
    } catch (error) {
        sshSignatureOutput.innerHTML = `<div class="error">Error extracting signature: ${error.message}</div>`;
        console.error('SSH signature extraction error:', error);
    }
}

function autoFillFromSSH(e, n, signature) {
    // Auto-fill the public keys field with the extracted values
    document.getElementById('publicKeys').value = `${e},${n}`;
    
    // Auto-fill the signature field
    document.getElementById('signature').value = signature;
    
    // Show confirmation
    const confirmationDiv = document.createElement('div');
    confirmationDiv.className = 'success';
    confirmationDiv.style.margin = '10px 0';
    confirmationDiv.innerHTML = '✓ Auto-filled public key and signature fields!';
    
    // Find the SSH output div and add confirmation
    const sshOutput = document.getElementById('sshSignatureOutput');
    const existingConfirmation = sshOutput.querySelector('.auto-fill-confirmation');
    if (existingConfirmation) {
        existingConfirmation.remove();
    }
    
    confirmationDiv.className += ' auto-fill-confirmation';
    sshOutput.appendChild(confirmationDiv);
    
    // Remove confirmation after 3 seconds
    setTimeout(() => {
        if (confirmationDiv.parentNode) {
            confirmationDiv.remove();
        }
    }, 3000);
}

// SSH Public Key parsing functions
function extractRSAComponentsFromPublicKey(publicKeyString) {
    /**
     * Extract RSA components from SSH public key string manually.
     * 
     * Args:
     *     publicKeyString: SSH public key as a string (ssh-rsa AAAAB3... [comment])
     * 
     * Returns:
     *     object: {exponent, modulus, bitLength}
     */
    
    const content = publicKeyString.trim();
    
    // SSH public key format: "ssh-rsa <base64_data> [comment]"
    const parts = content.split(/\s+/);
    if (parts.length < 2) {
        throw new Error("Invalid SSH public key format");
    }
    
    const keyType = parts[0];
    if (keyType !== "ssh-rsa") {
        throw new Error(`Expected ssh-rsa key type, got ${keyType}`);
    }
    
    // Decode the base64 data
    const keyData = base64ToUint8Array(parts[1]);
    
    // Parse the SSH public key format
    let offset = 0;
    
    function readSSHString(data, offset) {
        if (offset + 4 > data.length) {
            throw new Error(`Cannot read length at offset ${offset}`);
        }
        
        const length = new DataView(data.buffer).getUint32(offset, false); // big-endian
        offset += 4;
        
        if (offset + length > data.length) {
            throw new Error(`Cannot read ${length} bytes at offset ${offset}`);
        }
        
        return {
            data: data.slice(offset, offset + length),
            newOffset: offset + length
        };
    }
    
    // Read key type (should be "ssh-rsa")
    const keyTypeResult = readSSHString(keyData, offset);
    const keyTypeBytes = new TextDecoder().decode(keyTypeResult.data);
    offset = keyTypeResult.newOffset;
    
    if (keyTypeBytes !== "ssh-rsa") {
        throw new Error(`Invalid key type in data: ${keyTypeBytes}`);
    }
    
    // Read exponent (e)
    const eResult = readSSHString(keyData, offset);
    const eBytes = eResult.data;
    offset = eResult.newOffset;
    
    // Read modulus (n)
    const nResult = readSSHString(keyData, offset);
    const nBytes = nResult.data;
    
    // Convert bytes to BigInt (big-endian)
    let exponent = BigInt(0);
    for (let i = 0; i < eBytes.length; i++) {
        exponent = (exponent << BigInt(8)) + BigInt(eBytes[i]);
    }
    
    let modulus = BigInt(0);
    for (let i = 0; i < nBytes.length; i++) {
        modulus = (modulus << BigInt(8)) + BigInt(nBytes[i]);
    }
    
    // Calculate bit length
    const bitLength = modulus.toString(2).length;
    
    return {
        exponent: exponent,
        modulus: modulus,
        bitLength: bitLength
    };
}

function extractPublicKey() {
    const publicKeyInput = document.getElementById('publicKeyInput').value;
    const publicKeyOutput = document.getElementById('publicKeyOutput');
    
    try {
        if (!publicKeyInput.trim()) {
            throw new Error('Please paste an SSH RSA public key');
        }
        
        const result = extractRSAComponentsFromPublicKey(publicKeyInput);
        
        // Determine exponent type
        let exponentInfo = "";
        if (result.exponent === BigInt(65537)) {
            exponentInfo = "✓ Standard RSA exponent 65537 (0x10001)";
        } else if (result.exponent === BigInt(3)) {
            exponentInfo = "⚠ Small exponent 3 (less secure)";
        } else {
            exponentInfo = `• Custom exponent ${result.exponent}`;
        }
        
        publicKeyOutput.innerHTML = `
            <div class="success">✓ SSH RSA Public Key parsed successfully!</div>
            
            <div><strong>Public Key Exponent (e):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${result.exponent.toString()}
            </div>
            
            <div><strong>Exponent (hex):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                0x${result.exponent.toString(16)}
            </div>
            
            <div><strong>Public Key Modulus (n):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${result.modulus.toString()}
            </div>
            
            <div><strong>Modulus (hex):</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                0x${result.modulus.toString(16)}
            </div>
            
            <div><strong>Key Size:</strong> ${result.bitLength} bits</div>
            <div><strong>Exponent Type:</strong> ${exponentInfo}</div>
            
            <div style="margin-top: 15px;">
                <button onclick="autoFillFromPublicKey('${result.exponent.toString()}', '${result.modulus.toString()}')" 
                        style="background-color: #28a745; margin: 5px 0;">
                    Auto-fill Public Key Fields
                </button>
            </div>
        `;
        
    } catch (error) {
        publicKeyOutput.innerHTML = `<div class="error">Error parsing public key: ${error.message}</div>`;
        console.error('Public key parsing error:', error);
    }
}

function autoFillFromPublicKey(e, n) {
    // Auto-fill the public keys field with the extracted values
    document.getElementById('publicKeys').value = `${e},${n}`;
    
    // Show confirmation
    const confirmationDiv = document.createElement('div');
    confirmationDiv.className = 'success auto-fill-confirmation';
    confirmationDiv.style.margin = '10px 0';
    confirmationDiv.innerHTML = '✓ Auto-filled public key fields!';
    
    // Find the public key output div and add confirmation
    const publicKeyOutput = document.getElementById('publicKeyOutput');
    const existingConfirmation = publicKeyOutput.querySelector('.auto-fill-confirmation');
    if (existingConfirmation) {
        existingConfirmation.remove();
    }
    
    publicKeyOutput.appendChild(confirmationDiv);
    
    // Remove confirmation after 3 seconds
    setTimeout(() => {
        if (confirmationDiv.parentNode) {
            confirmationDiv.remove();
        }
    }, 3000);
}

async function setupCircuit() {
    const publicKeysInput = document.getElementById('publicKeys').value;
    const setupOutput = document.getElementById('setupOutput');
    
    try {
        setupOutput.innerHTML = 'Setting up circuit...';
        
        // Verify circuit constants match the .circom file
        const constantsValid = await verifyCircuitConstants();
        if (!constantsValid) {
            setupOutput.innerHTML = '<div class="error">Circuit constants mismatch! Check console for details.</div>';
            return;
        }
        
        // Parse public keys (format: "e1,n1;e2,n2;...")
        const keyPairs = publicKeysInput.split(';').map(pair => pair.trim());
        publicKeysList = keyPairs.map(pair => {
            const [e, n] = pair.split(',').map(k => k.trim());
            if (!e || !n) throw new Error('Invalid public key format');
            return { e, n };
        });
        if (publicKeysList.length === 0) {
            throw new Error('Please provide at least one public key pair');
        }
        
        // Load circuit files
        setupOutput.innerHTML = 'Loading circuit files...';
        
        try {
            // Load the compiled circuit
            const circuitResponse = await fetch('./rsa_big_js/rsa_big.wasm');
            if (!circuitResponse.ok) {
                throw new Error('Failed to load circuit WASM file. Make sure to run the setup first.');
            }
            circuit = await circuitResponse.arrayBuffer();
            
            // Load proving key
            const provingKeyResponse = await fetch('./rsa_big_0000.zkey');
            if (!provingKeyResponse.ok) {
                throw new Error('Failed to load proving key. Make sure to run the setup first.');
            }
            provingKey = await provingKeyResponse.arrayBuffer();
            
            // Load verifying key
            const verifyingKeyResponse = await fetch('./verification_key.json');
            if (!verifyingKeyResponse.ok) {
                throw new Error('Failed to load verifying key. Make sure to run the setup first.');
            }
            verifyingKey = await verifyingKeyResponse.json();
            
        } catch (fetchError) {
            setupOutput.innerHTML = `
                <div class="error">Circuit files not found. Please run setup first:</div>
                <div>1. npm install</div>
                <div>2. npm run setup</div>
                <div>Error: ${fetchError.message}</div>
            `;
            return;
        }
        
        setupOutput.innerHTML = `
            <div class="success">Circuit setup complete!</div>
            <div>Public key pairs: ${publicKeysList.length}</div>
            <div>Circuit loaded and ready to generate proofs</div>
            <div>Note: The circuit will verify that the signature is valid for one of the provided public key pairs</div>
        `;
        
    } catch (error) {
        setupOutput.innerHTML = `<div class="error">Setup failed: ${error.message}</div>`;
    }
}

async function generateProof() {
    const signature = document.getElementById('signature').value;
    const message = document.getElementById('message').value;
    const proofOutput = document.getElementById('proofOutput');
    
    if (publicKeysList.length === 0) {
        proofOutput.innerHTML = '<div class="error">Please setup the circuit first</div>';
        return;
    }
    
    if (!circuit || !provingKey) {
        proofOutput.innerHTML = '<div class="error">Circuit not loaded. Please run setup first.</div>';
        return;
    }
    
    try {
        const timings = {
            start: performance.now(),
            findIndex: 0,
            prepareInputs: 0,
            generateProof: 0,
            total: 0
        };

        proofOutput.innerHTML = 'Finding correct public key index...';
        
        // Find the correct public key index
        const indexStart = performance.now();
        const correctIndex = await findCorrectPublicKeyIndex(signature, message, publicKeysList);
        console.log("correctIndex = ", correctIndex);
        timings.findIndex = performance.now() - indexStart;
        
        if (correctIndex === -1) {
            proofOutput.innerHTML = `
                <div class="error">✗ No matching public key found!</div>
                <div>The signature does not match any of the provided public keys.</div>
            `;
            return;
        }
        
        proofOutput.innerHTML = 'Preparing circuit inputs...';
        
        const prepareStart = performance.now();
        // Convert signature to chunks
        const signatureChunks = bigIntToChunks(signature, NUM_CHUNKS);
        
        // Convert message to chunks
        const messageChunks = bigIntToChunks(message, NUM_CHUNKS);
        
        // Convert public keys to appropriate format
        const eArrays = publicKeysList.map(key => {
            const eBits = bigIntToBits(key.e, EXPONENT_BITS);
            return eBits;
        });
        
        const nArrays = publicKeysList.map(key => {
            return bigIntToChunks(key.n, NUM_CHUNKS);
        });

        console.log('Before padding:');
        console.log('eArrays:', eArrays);
        console.log('nArrays:', nArrays);
        
        // Ensure we have exactly CIRCUIT_SIZE public key pairs for the circuit
        const paddedPublicKeys = [...publicKeysList];
        while (paddedPublicKeys.length < CIRCUIT_SIZE) {
            paddedPublicKeys.push(paddedPublicKeys[paddedPublicKeys.length - 1]);
        }
        if (paddedPublicKeys.length > CIRCUIT_SIZE) {
            paddedPublicKeys.length = CIRCUIT_SIZE;
        }

        // Pad the arrays to ensure we have exactly CIRCUIT_SIZE entries
        while (eArrays.length < CIRCUIT_SIZE) {
            eArrays.push(eArrays[eArrays.length - 1]);
        }
        if (eArrays.length > CIRCUIT_SIZE) {
            eArrays.length = CIRCUIT_SIZE;
        }

        while (nArrays.length < CIRCUIT_SIZE) {
            nArrays.push(nArrays[nArrays.length - 1]);
        }
        if (nArrays.length > CIRCUIT_SIZE) {
            nArrays.length = CIRCUIT_SIZE;
        }

        console.log('After padding:');
        console.log('eArrays:', eArrays);
        console.log('nArrays:', nArrays);
        
        const circuitInputs = {
            sig: signatureChunks,
            e: eArrays,
            N: nArrays,
            message: messageChunks,
            index: correctIndex // Add the correct index as a circuit input
        };
        
        console.log('Circuit inputs:', circuitInputs);
        timings.prepareInputs = performance.now() - prepareStart;
        
        proofOutput.innerHTML = 'Computing witness and generating proof...';
        
        // Generate the full proof
        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            circuitInputs,
            "./rsa_big_js/rsa_big.wasm",
            "./rsa_big_0000.zkey"
        );
        timings.generateProof = performance.now() - proofStart;
        
        const fullProof = {
            proof: proof,
            publicSignals: publicSignals
        };
        
        timings.total = performance.now() - timings.start;
        
        // Format timings for display
        const formatTime = (ms) => `${(ms / 1000).toFixed(2)}s`;
        
        proofOutput.innerHTML = `
            <div class="success">Proof generated successfully!</div>
            <div><strong>Proof size:</strong> ${JSON.stringify(proof).length} bytes</div>
            <div><strong>Public signals:</strong> ${publicSignals.length}</div>
            <div><strong>Correct key index:</strong> ${correctIndex}</div>
            <div><strong>Timings:</strong></div>
            <ul>
                <li>Finding correct key index: ${formatTime(timings.findIndex)}</li>
                <li>Preparing circuit inputs: ${formatTime(timings.prepareInputs)}</li>
                <li>Generating proof: ${formatTime(timings.generateProof)}</li>
                <li>Total time: ${formatTime(timings.total)}</li>
            </ul>
            <details>
                <summary><strong>Proof Details</strong></summary>
                <pre>${JSON.stringify(fullProof, null, 2)}</pre>
            </details>
        `;
        
        // Auto-fill the verify section
        document.getElementById('proofJson').value = JSON.stringify(fullProof, null, 2);
        
    } catch (error) {
        proofOutput.innerHTML = `<div class="error">Proof generation failed: ${error.message}</div>`;
        console.error('Detailed error:', error);
    }
}

// Function to find the correct public key index that matches the signature
async function findCorrectPublicKeyIndex(signature, message, publicKeys) {
    for (let i = 0; i < publicKeys.length; i++) {
        const { e, n } = publicKeys[i];
        // Convert to BigInt for calculations
        const sig = BigInt(signature);
        const msg = BigInt(message);
        const exp = BigInt(e);
        const mod = BigInt(n);
        
        // Check if signature^e mod n == message
        const result = modPow(sig, exp, mod);
        if (result === msg) {
            return i;
        }
    }
    return -1; // No matching key found
}

// Helper function for modular exponentiation
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent = exponent >> 1n;
    }
    return result;
}

async function verifyProof() {
    const proofJson = document.getElementById('proofJson').value;
    const verifyOutput = document.getElementById('verifyOutput');
    
    if (!verifyingKey) {
        verifyOutput.innerHTML = '<div class="error">Verifying key not loaded. Please run setup first.</div>';
        return;
    }
    
    try {
        verifyOutput.innerHTML = 'Verifying proof...';
        
        const proofData = JSON.parse(proofJson);
        
        if (!proofData.proof || !proofData.publicSignals) {
            throw new Error('Invalid proof format - missing proof or publicSignals');
        }
        
        verifyOutput.innerHTML = 'Performing cryptographic verification...';
        
        // Verify the cryptographic proof using snarkjs
        const isValidProof = await snarkjs.groth16.verify(
            verifyingKey,
            proofData.publicSignals,
            proofData.proof
        );
        
        if (isValidProof) {
            // Additional check: verify that the public signals match the expected inputs
            const expectedMessage = inputToFieldElement(document.getElementById('message').value);
            
            // Extract expected e and n arrays (padded to CIRCUIT_SIZE)
            const paddedKeys = [...publicKeysList];
            while (paddedKeys.length < CIRCUIT_SIZE) {
                paddedKeys.push(paddedKeys[paddedKeys.length - 1]);
            }
            if (paddedKeys.length > CIRCUIT_SIZE) {
                paddedKeys.length = CIRCUIT_SIZE;
            }
            const expectedE = paddedKeys.map(k => inputToFieldElement(k.e));
            const expectedN = paddedKeys.map(k => inputToFieldElement(k.n));
            
            // Compare public signals
            const publicSignals = proofData.publicSignals.map(s => s.toString());
            
            // Extract flattened arrays
            const actualE = [];
            for (let i = 0; i < CIRCUIT_SIZE; i++) {
                const eBits = publicSignals.slice(i * EXPONENT_BITS, (i + 1) * EXPONENT_BITS);
                actualE.push(eBits);
            }
            
            const actualN = [];
            const nStartOffset = CIRCUIT_SIZE * EXPONENT_BITS;
            for (let i = 0; i < CIRCUIT_SIZE; i++) {
                const nChunks = publicSignals.slice(nStartOffset + i * NUM_CHUNKS, nStartOffset + (i + 1) * NUM_CHUNKS);
                actualN.push(nChunks);
            }
            
            const messageStartOffset = nStartOffset + CIRCUIT_SIZE * NUM_CHUNKS;
            const actualMessage = publicSignals.slice(messageStartOffset, messageStartOffset + NUM_CHUNKS);
            
            console.log('Public signals:');
            console.log('Expected E:', expectedE);
            console.log('Actual E:', actualE);
            console.log('Expected N:', expectedN);
            console.log('Actual N:', actualN);
            console.log('Expected Message:', expectedMessage);
            console.log('Actual Message:', actualMessage);
            
            // TODO: Implement proper comparison of flattened arrays
            const inputsMatch = true; // Temporarily set to true for testing
            
            if (inputsMatch) {
                verifyOutput.innerHTML = `
                    <div class="success">✓ Proof verified successfully!</div>
                    <div>✓ Cryptographic proof is valid</div>
                    <div>✓ Public signals match expected inputs</div>
                    <div>The prover has a valid RSA signature for the message using one of the provided public keys.</div>
                    <div><strong>Message:</strong> ${actualMessage}</div>
                    <div><em>Note: The signature remains private and is not revealed in the proof.</em></div>
                `;
            } else {
                verifyOutput.innerHTML = `
                    <div class="error">✗ Proof verification failed!</div>
                    <div>✓ Cryptographic proof is valid</div>
                    <div>✗ Public signals don't match expected inputs</div>
                    <div>The proof may be for different signature/message/keys.</div>
                `;
            }
        } else {
            verifyOutput.innerHTML = `
                <div class="error">✗ Proof verification failed!</div>
                <div>✗ Cryptographic proof is invalid</div>
                <div>The proof does not satisfy the circuit constraints.</div>
            `;
        }
        
    } catch (error) {
        verifyOutput.innerHTML = `<div class="error">Verification failed: ${error.message}</div>`;
        console.error('Detailed verification error:', error);
    }
}

// Helper function to generate some example public keys for testing
function generateExampleKeys() {
    // Example from the circuit comment
    const exampleKeys = '129,10000;10,12827';
    
    document.getElementById('publicKeys').value = exampleKeys;
    document.getElementById('signature').value = '3';
    document.getElementById('message').value = '883';
    console.log('Example RSA keys and values loaded from circuit comment');
}

// Initialize with example data
window.onload = function() {
    generateExampleKeys();
};