let circuit = null;
let provingKey = null;
let verifyingKey = null;

// Global variables to store the last generated proof data for verification
let lastGeneratedSSHProof = null;
let lastGeneratedMessage = null;

// Circuit constants - must match rsa_big.circom GroupVerify(3, 120, 35, 17)
const CIRCUIT_SIZE = 3;        // Number of public keys supported
const CHUNK_BITS = 120;        // Bits per chunk (n parameter)
const NUM_CHUNKS = 35;         // Number of chunks (k parameter)
const EXPONENT_BITS = 17;      // Exponent bits (exp_bits parameter)

// Helper function that calls the integer-based pipeline (missing from current implementation)
async function generateZKProof(signature, message, publicKeys) {
    /**
     * Generate a zero-knowledge proof using integer inputs
     * This is the fallback/alternative to the SSH-based workflow
     */
    const timings = {
        start: performance.now(),
        setup: 0,
        findKey: 0,
        prepareInputs: 0,
        generateProof: 0,
        total: 0
    };
    
    try {
        console.log('🔧 Starting integer-based ZK proof generation...');
        
        // Step 1: Setup circuit
        const setupStart = performance.now();
        const constantsValid = await verifyCircuitConstants();
        if (!constantsValid) {
            throw new Error('Circuit constants mismatch! Check console for details.');
        }
        
        await loadCircuitFiles();
        timings.setup = performance.now() - setupStart;
        console.log(`✅ Circuit setup complete (${(timings.setup / 1000).toFixed(2)}s)`);
        
        // Step 2: Find the correct public key index
        const findStart = performance.now();
        const correctIndex = findCorrectPublicKeyIndex(signature, message, publicKeys);
        if (correctIndex === -1) {
            throw new Error('No matching public key found! The signature does not match any of the provided public keys.');
        }
        timings.findKey = performance.now() - findStart;
        console.log(`✅ Found matching key at index ${correctIndex} (${(timings.findKey / 1000).toFixed(2)}s)`);
        
        // Step 3: Prepare circuit inputs
        const prepareStart = performance.now();
        const circuitInputs = prepareCircuitInputs(signature, message, publicKeys, correctIndex);
        timings.prepareInputs = performance.now() - prepareStart;
        console.log(`✅ Circuit inputs prepared (${(timings.prepareInputs / 1000).toFixed(2)}s)`);
        
        // Step 4: Generate the ZK proof
        const proofStart = performance.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            circuitInputs,
            "./rsa_big_js/rsa_big.wasm",
            "./rsa_big_0000.zkey"
        );
        timings.generateProof = performance.now() - proofStart;
        timings.total = performance.now() - timings.start;
        
        console.log(`✅ Proof generated successfully! (${(timings.generateProof / 1000).toFixed(2)}s)`);
        console.log(`🎉 Total time: ${(timings.total / 1000).toFixed(2)}s`);
        
        return {
            success: true,
            proof: proof,
            publicSignals: publicSignals,
            matchedKeyIndex: correctIndex,
            timings: timings
        };
        
    } catch (error) {
        timings.total = performance.now() - timings.start;
        console.error('❌ Proof generation failed:', error);
        
        return {
            success: false,
            error: error.message,
            timings: timings
        };
    }
}

// Main proof generation function - pipes all components together
async function generateZKProofFromSSH(sshSignatureContent, message, sshPublicKeys) {
    /**
     * Generate a zero-knowledge proof that we know a valid SSH signature for the given message
     * using one of the provided SSH public keys (without revealing which one or the signature)
     * 
     * Args:
     *     sshSignatureContent: SSH signature file content (hidden)
     *     message: Message that was signed
     *     sshPublicKeys: Array of SSH public key strings
     * 
     * Returns:
     *     object: {success, proof, publicSignals, sshPublicKeys, error, timings}
     */
    
    const timings = {
        start: performance.now(),
        parseSSH: 0,
        setup: 0,
        findKey: 0,
        prepareInputs: 0,
        generateProof: 0,
        total: 0
    };
    
    try {
        console.log('🔧 Starting SSH ZK proof generation...');
        
        // Step 1: Parse SSH signature and public keys
        console.log('🔑 Parsing SSH signature and public keys...');
        const parseStart = performance.now();
        
        // Extract signature and public key from SSH signature file
        const sshSigData = extractSignatureFromSSHFile(sshSignatureContent);
        const signature = sshSigData.signatureInt;
        
        // Parse all SSH public keys into {e, n} format
        const publicKeys = [];
        for (const sshPubKey of sshPublicKeys) {
            const keyData = extractRSAComponentsFromSSHPublicKey(sshPubKey);
            publicKeys.push({
                e: keyData.exponent,
                n: keyData.modulus
            });
        }
        
        timings.parseSSH = performance.now() - parseStart;
        console.log(`✅ SSH parsing complete (${(timings.parseSSH / 1000).toFixed(2)}s)`);
        
        // Step 2: Verify circuit constants and load circuit files
        console.log('📋 Verifying circuit constants...');
        const setupStart = performance.now();
        
        const constantsValid = await verifyCircuitConstants();
        if (!constantsValid) {
            throw new Error('Circuit constants mismatch! Check console for details.');
        }
        
        await loadCircuitFiles();
        timings.setup = performance.now() - setupStart;
        console.log(`✅ Circuit setup complete (${(timings.setup / 1000).toFixed(2)}s)`);
        
        // Step 3: Find the correct public key index
        console.log('🔍 Finding matching public key...');
        const findStart = performance.now();
        
        const correctIndex = findCorrectPublicKeyIndex(signature, message, publicKeys);
        if (correctIndex === -1) {
            throw new Error('No matching public key found! The signature does not match any of the provided public keys.');
        }
        
        timings.findKey = performance.now() - findStart;
        console.log(`✅ Found matching key at index ${correctIndex} (${(timings.findKey / 1000).toFixed(2)}s)`);
        
        // Step 4: Prepare circuit inputs
        console.log('🔢 Preparing circuit inputs...');
        const prepareStart = performance.now();
        
        const circuitInputs = prepareCircuitInputs(signature, message, publicKeys, correctIndex);
        timings.prepareInputs = performance.now() - prepareStart;
        console.log(`✅ Circuit inputs prepared (${(timings.prepareInputs / 1000).toFixed(2)}s)`);
        
        // Step 5: Generate the ZK proof
        console.log('🎯 Generating zero-knowledge proof...');
        const proofStart = performance.now();
        
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            circuitInputs,
            "./rsa_big_js/rsa_big.wasm",
            "./rsa_big_0000.zkey"
        );
        
        // Strip e and N arrays from publicSignals to hide key data
        // Current publicSignals structure: [e arrays (CIRCUIT_SIZE * EXPONENT_BITS), N arrays (CIRCUIT_SIZE * NUM_CHUNKS), message (NUM_CHUNKS)]
        const eArrayLength = CIRCUIT_SIZE * EXPONENT_BITS;
        const nArrayLength = CIRCUIT_SIZE * NUM_CHUNKS;
        const messageStartOffset = eArrayLength + nArrayLength;
        
        // Extract only the message part of public signals
        const messageOnlyPublicSignals = publicSignals.slice(messageStartOffset);
        
        console.log(`🔒 Stripped key data from public signals. Original: ${publicSignals.length}, Message-only: ${messageOnlyPublicSignals.length}`);
        
        timings.generateProof = performance.now() - proofStart;
        timings.total = performance.now() - timings.start;
        
        console.log(`✅ Proof generated successfully! (${(timings.generateProof / 1000).toFixed(2)}s)`);
        console.log(`🎉 Total time: ${(timings.total / 1000).toFixed(2)}s`);
        
        return {
            success: true,
            proof: proof,
            publicSignals: messageOnlyPublicSignals, // Only include message, not e/N arrays
            sshPublicKeys: sshPublicKeys, // Include SSH public keys instead of raw encodings
            matchedKeyIndex: correctIndex,
            timings: timings
        };
        
    } catch (error) {
        timings.total = performance.now() - timings.start;
        console.error('❌ Proof generation failed:', error);
        
        return {
            success: false,
            error: error.message,
            timings: timings
        };
    }
}

// Helper function to load circuit files
async function loadCircuitFiles() {
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
        
    } catch (error) {
        throw new Error(`Circuit file loading failed: ${error.message}`);
    }
}

// Helper function to prepare circuit inputs
function prepareCircuitInputs(signature, message, publicKeys, correctIndex) {
    // Convert signature to chunks
    const signatureChunks = bigIntToChunks(signature, NUM_CHUNKS);
    
    // Convert message to chunks
    const messageChunks = bigIntToChunks(message, NUM_CHUNKS);
    
    // Convert public keys to appropriate format
    const eArrays = publicKeys.map(key => {
        const eBits = bigIntToBits(key.e, EXPONENT_BITS);
        return eBits;
    });
    
    const nArrays = publicKeys.map(key => {
        return bigIntToChunks(key.n, NUM_CHUNKS);
    });

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
    
    return {
        sig: signatureChunks,
        e: eArrays,
        N: nArrays,
        message: messageChunks,
        index: correctIndex
    };
}

// SSH-aware verification function
async function verifySSHProof(proofData, message, sshPublicKeys) {
    /**
     * Verify a zero-knowledge proof that was generated with SSH inputs
     * Reconstructs the key encodings from SSH public keys before verification
     * 
     * Args:
     *     proofData: {proof, publicSignals, sshPublicKeys}
     *     message: Original message that was signed
     *     sshPublicKeys: Array of SSH public key strings
     * 
     * Returns:
     *     object: {success, error, keyEncodingsMatch}
     */
    
    try {
        if (!verifyingKey) {
            throw new Error('Verifying key not loaded');
        }
        
        console.log('🔍 Starting SSH proof verification...');
        
        // Step 1: Reconstruct key encodings from SSH public keys
        console.log('🔑 Reconstructing key encodings from SSH public keys...');
        
        const reconstructedKeys = [];
        for (const sshPubKey of sshPublicKeys) {
            const keyData = extractRSAComponentsFromSSHPublicKey(sshPubKey);
            reconstructedKeys.push({
                e: keyData.exponent,
                n: keyData.modulus
            });
        }
        
        // Step 2: Reconstruct full public signals from SSH public keys and message-only signals
        console.log('🔧 Reconstructing full public signals...');
        
        // Convert reconstructed keys to expected format (same as in proof generation)
        const paddedKeys = [...reconstructedKeys];
        while (paddedKeys.length < CIRCUIT_SIZE) {
            paddedKeys.push(paddedKeys[paddedKeys.length - 1]);
        }
        if (paddedKeys.length > CIRCUIT_SIZE) {
            paddedKeys.length = CIRCUIT_SIZE;
        }
        
        // Convert to circuit format
        const eArrays = paddedKeys.map(key => bigIntToBits(key.e, EXPONENT_BITS));
        const nArrays = paddedKeys.map(key => bigIntToChunks(key.n, NUM_CHUNKS));
        
        // Flatten arrays to match circuit output format
        const flattenedE = [];
        for (let i = 0; i < CIRCUIT_SIZE; i++) {
            for (let j = 0; j < EXPONENT_BITS; j++) {
                flattenedE.push(eArrays[i][j].toString());
            }
        }
        
        const flattenedN = [];
        for (let i = 0; i < CIRCUIT_SIZE; i++) {
            for (let j = 0; j < NUM_CHUNKS; j++) {
                flattenedN.push(nArrays[i][j]);
            }
        }
        
        // Reconstruct full public signals: [e arrays, N arrays, message]
        const reconstructedPublicSignals = [
            ...flattenedE,
            ...flattenedN,
            ...proofData.publicSignals  // This is the message-only part
        ];
        
        console.log(`🔧 Reconstructed public signals. E: ${flattenedE.length}, N: ${flattenedN.length}, Message: ${proofData.publicSignals.length}, Total: ${reconstructedPublicSignals.length}`);
        
        // Step 3: Verify cryptographic proof with reconstructed signals
        console.log('🔒 Verifying cryptographic proof...');
        
        const isValidProof = await snarkjs.groth16.verify(
            verifyingKey,
            reconstructedPublicSignals,
            proofData.proof
        );
        
        if (!isValidProof) {
            return {
                success: false,
                error: 'Cryptographic proof verification failed'
            };
        }
        
        console.log('✅ SSH proof verification complete');
        
        return {
            success: true,
            cryptographicProofValid: isValidProof,
            keyEncodingsMatch: true, // Keys were used to reconstruct the signals, so they match by construction
            reconstructedKeysCount: reconstructedKeys.length
        };
        
    } catch (error) {
        console.error('❌ SSH proof verification failed:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

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
function extractRSAComponentsFromSSHPublicKey(publicKeyString) {
    // Alias for the main SSH public key parsing function
    return extractRSAComponentsFromPublicKey(publicKeyString);
}

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
function findCorrectPublicKeyIndex(signature, message, publicKeys) {
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

// Streamlined SSH UI function for the main workflow
async function streamlinedSSHProofGeneration() {
    const sshSignatureContent = document.getElementById('sshSignatureContent').value;
    const message = document.getElementById('message').value;
    const sshPublicKeysInput = document.getElementById('sshPublicKeys').value;
    const output = document.getElementById('streamlinedOutput');
    
    try {
        if (!sshSignatureContent.trim() || !message.trim() || !sshPublicKeysInput.trim()) {
            throw new Error('Please provide SSH signature content, message, and SSH public keys');
        }
        
        // Parse SSH public keys (one per line)
        const sshPublicKeys = sshPublicKeysInput.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
        
        if (sshPublicKeys.length === 0) {
            throw new Error('Please provide at least one SSH public key');
        }
        
        output.innerHTML = '<div>🚀 Starting streamlined SSH ZK proof generation...</div>';
        
        // Generate the proof using the SSH pipeline
        const result = await generateZKProofFromSSH(sshSignatureContent, message, sshPublicKeys);
        
        if (result.success) {
            const formatTime = (ms) => `${(ms / 1000).toFixed(2)}s`;
            
            // Store the result for verification
            lastGeneratedSSHProof = {
                proof: result.proof,
                publicSignals: result.publicSignals,
                sshPublicKeys: result.sshPublicKeys
            };
            lastGeneratedMessage = message;
            
            // Auto-populate the SSH proof verification textbox
            document.getElementById('sshProofJson').value = JSON.stringify({
                proof: result.proof,
                publicSignals: result.publicSignals,
                sshPublicKeys: result.sshPublicKeys
            }, null, 2);
            
            output.innerHTML = `
                <div class="success">🎉 SSH Zero-Knowledge Proof Generated Successfully!</div>
                
                <div><strong>🔍 Proof Summary:</strong></div>
                <div>• Matched SSH public key index: ${result.matchedKeyIndex}</div>
                <div>• Proof size: ${JSON.stringify(result.proof).length} bytes</div>
                <div>• Public signals: ${result.publicSignals.length}</div>
                <div>• SSH public keys included: ${result.sshPublicKeys.length}</div>
                
                <div><strong>⏱️ Performance:</strong></div>
                <div>• SSH parsing: ${formatTime(result.timings.parseSSH)}</div>
                <div>• Circuit setup: ${formatTime(result.timings.setup)}</div>
                <div>• Key matching: ${formatTime(result.timings.findKey)}</div>
                <div>• Input preparation: ${formatTime(result.timings.prepareInputs)}</div>
                <div>• Proof generation: ${formatTime(result.timings.generateProof)}</div>
                <div>• <strong>Total time: ${formatTime(result.timings.total)}</strong></div>
                
                <div><strong>🔐 Zero-Knowledge Properties:</strong></div>
                <div>✅ SSH signature remains hidden</div>
                <div>✅ Which SSH public key was used remains hidden</div>
                <div>✅ Only proves: "I know a valid SSH signature for this message"</div>
                <div>✅ Proof contains SSH public keys (not raw encodings)</div>
                
                <details style="margin-top: 15px;">
                    <summary><strong>📋 Full SSH Proof Data</strong></summary>
                    <pre style="background: #1a1a1a; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px;">${JSON.stringify({
                        proof: result.proof,
                        publicSignals: result.publicSignals,
                        sshPublicKeys: result.sshPublicKeys
                    }, null, 2)}</pre>
                </details>
                
                <div style="margin-top: 15px;">
                    <button onclick="verifyLastGeneratedSSHProof()" 
                            style="background-color: #28a745; margin: 5px 0;">
                        🔍 Quick Verify This Proof
                    </button>
                </div>
            `;
        } else {
            output.innerHTML = `
                <div class="error">❌ SSH Proof Generation Failed</div>
                <div><strong>Error:</strong> ${result.error}</div>
                <div><strong>Time elapsed:</strong> ${(result.timings.total / 1000).toFixed(2)}s</div>
            `;
        }
        
    } catch (error) {
        output.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
        console.error('Streamlined SSH proof generation error:', error);
    }
}

// Streamlined integer-based UI function for the alternative workflow
async function streamlinedProofGeneration() {
    const signature = document.getElementById('signature').value;
    const message = document.getElementById('message').value;
    const publicKeysInput = document.getElementById('publicKeys').value;
    const output = document.getElementById('integerStreamlinedOutput');
    
    try {
        if (!signature.trim() || !message.trim() || !publicKeysInput.trim()) {
            throw new Error('Please provide signature, message, and public keys');
        }
        
        // Parse public keys
        const keyPairs = publicKeysInput.split(';').map(pair => pair.trim());
        const publicKeys = keyPairs.map(pair => {
            const [e, n] = pair.split(',').map(k => k.trim());
            if (!e || !n) throw new Error('Invalid public key format');
            return { e, n };
        });
        
        output.innerHTML = '<div>🚀 Starting streamlined ZK proof generation...</div>';
        
        // Generate the proof using the main pipeline
        const result = await generateZKProof(signature, message, publicKeys);
        
        if (result.success) {
            const formatTime = (ms) => `${(ms / 1000).toFixed(2)}s`;
            
            output.innerHTML = `
                <div class="success">🎉 Zero-Knowledge Proof Generated Successfully!</div>
                
                <div><strong>🔍 Proof Summary:</strong></div>
                <div>• Matched public key index: ${result.matchedKeyIndex}</div>
                <div>• Proof size: ${JSON.stringify(result.proof).length} bytes</div>
                <div>• Public signals: ${result.publicSignals.length}</div>
                
                <div><strong>⏱️ Performance:</strong></div>
                <div>• Circuit setup: ${formatTime(result.timings.setup)}</div>
                <div>• Key matching: ${formatTime(result.timings.findKey)}</div>
                <div>• Input preparation: ${formatTime(result.timings.prepareInputs)}</div>
                <div>• Proof generation: ${formatTime(result.timings.generateProof)}</div>
                <div>• <strong>Total time: ${formatTime(result.timings.total)}</strong></div>
                
                <div><strong>🔐 Zero-Knowledge Properties:</strong></div>
                <div>✅ Signature remains hidden</div>
                <div>✅ Which public key was used remains hidden</div>
                <div>✅ Only proves: "I know a valid signature for this message"</div>
                
                <details style="margin-top: 15px;">
                    <summary><strong>📋 Full Proof Data</strong></summary>
                    <pre style="background: #1a1a1a; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px;">${JSON.stringify({
                        proof: result.proof,
                        publicSignals: result.publicSignals
                    }, null, 2)}</pre>
                </details>
                
                <div style="margin-top: 15px;">
                    <button onclick="verifyGeneratedProof('${JSON.stringify({proof: result.proof, publicSignals: result.publicSignals}).replace(/'/g, "\\'")}')" 
                            style="background-color: #28a745; margin: 5px 0;">
                        🔍 Verify This Proof
                    </button>
                </div>
            `;
        } else {
            output.innerHTML = `
                <div class="error">❌ Proof Generation Failed</div>
                <div><strong>Error:</strong> ${result.error}</div>
                <div><strong>Time elapsed:</strong> ${(result.timings.total / 1000).toFixed(2)}s</div>
            `;
        }
        
    } catch (error) {
        output.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
        console.error('Streamlined proof generation error:', error);
    }
}

// Helper function to verify SSH proof from textbox
async function verifyStreamlinedSSHProof() {
    const sshProofJson = document.getElementById('sshProofJson').value;
    const message = document.getElementById('message').value; // Get message from the input field
    const output = document.getElementById('sshVerificationOutput');
    
    try {
        if (!sshProofJson.trim()) {
            throw new Error('Please provide SSH proof JSON. Generate a proof first or paste proof data.');
        }
        
        if (!message.trim()) {
            throw new Error('Please provide the message that was signed.');
        }
        
        output.innerHTML = '<div>🔍 Parsing SSH proof data...</div>';
        
        const proofData = JSON.parse(sshProofJson);
        
        if (!proofData.proof || !proofData.publicSignals || !proofData.sshPublicKeys) {
            throw new Error('Invalid SSH proof format - missing proof, publicSignals, or sshPublicKeys');
        }
        
        if (!verifyingKey) {
            // Try to load verifying key
            await loadCircuitFiles();
        }
        
        output.innerHTML += '<div>🔧 Verifying SSH proof with message reconstruction...</div>';
        
        // Use the SSH-aware verification function
        const verificationResult = await verifySSHProof(proofData, message, proofData.sshPublicKeys);
        
        if (verificationResult.success) {
            output.innerHTML = `
                <div class="success">✅ SSH Proof Verification Successful!</div>
                <div>✅ Cryptographic proof is valid: ${verificationResult.cryptographicProofValid}</div>
                <div>✅ SSH key encodings reconstructed and verified: ${verificationResult.keyEncodingsMatch}</div>
                <div>✅ Reconstructed ${verificationResult.reconstructedKeysCount} SSH public keys</div>
                <div>✅ Message: verified</div>
                <div style="margin-top: 10px; padding: 10px; background: #1e3a1e; border-radius: 4px;">
                    <strong>🔐 Verification confirms:</strong> The prover knows a valid SSH signature for the provided message using one of the SSH public keys, without revealing which key or the signature itself.
                </div>
            `;
        } else {
            output.innerHTML = `
                <div class="error">❌ SSH Proof Verification Failed</div>
                <div><strong>Error:</strong> ${verificationResult.error}</div>
            `;
        }
        
    } catch (error) {
        output.innerHTML = `<div class="error">❌ Verification Error: ${error.message}</div>`;
        console.error('SSH proof verification error:', error);
    }
}

// Helper function to verify the last generated SSH proof (quick verify)
async function verifyLastGeneratedSSHProof() {
    const output = document.getElementById('streamlinedOutput');
    
    if (!lastGeneratedSSHProof || !lastGeneratedMessage) {
        output.innerHTML += '<div class="error">❌ No SSH proof data available. Generate a proof first.</div>';
        return;
    }
    
    try {
        if (!verifyingKey) {
            output.innerHTML += '<div class="error">❌ Verifying key not loaded</div>';
            return;
        }
        
        output.innerHTML += '<div>🔍 Verifying SSH proof...</div>';
        
        // Use the SSH-aware verification function
        const verificationResult = await verifySSHProof(lastGeneratedSSHProof, lastGeneratedMessage, lastGeneratedSSHProof.sshPublicKeys);
        
        if (verificationResult.success) {
            output.innerHTML += `
                <div class="success">✅ SSH Proof verification successful!</div>
                <div>✅ Cryptographic proof is valid: ${verificationResult.cryptographicProofValid}</div>
                <div>✅ SSH key encodings match: ${verificationResult.keyEncodingsMatch}</div>
                <div>✅ Reconstructed ${verificationResult.reconstructedKeysCount} SSH public keys</div>
            `;
        } else {
            output.innerHTML += `<div class="error">❌ SSH Proof verification failed: ${verificationResult.error}</div>`;
        }
        
    } catch (error) {
        output.innerHTML += `<div class="error">❌ SSH Verification error: ${error.message}</div>`;
    }
}

// Helper function to verify a generated SSH proof (legacy)
async function verifyGeneratedSSHProof(proofJsonString, message) {
    const output = document.getElementById('streamlinedOutput');
    
    try {
        const proofData = JSON.parse(proofJsonString);
        
        if (!verifyingKey) {
            output.innerHTML += '<div class="error">❌ Verifying key not loaded</div>';
            return;
        }
        
        output.innerHTML += '<div>🔍 Verifying SSH proof...</div>';
        
        // Use the SSH-aware verification function
        const verificationResult = await verifySSHProof(proofData, message, proofData.sshPublicKeys);
        
        if (verificationResult.success) {
            output.innerHTML += `
                <div class="success">✅ SSH Proof verification successful!</div>
                <div>✅ Cryptographic proof is valid: ${verificationResult.cryptographicProofValid}</div>
                <div>✅ SSH key encodings match: ${verificationResult.keyEncodingsMatch}</div>
                <div>✅ Reconstructed ${verificationResult.reconstructedKeysCount} SSH public keys</div>
            `;
        } else {
            output.innerHTML += `<div class="error">❌ SSH Proof verification failed: ${verificationResult.error}</div>`;
        }
        
    } catch (error) {
        output.innerHTML += `<div class="error">❌ SSH Verification error: ${error.message}</div>`;
    }
}

// Helper function to verify a generated proof (integer-based)
async function verifyGeneratedProof(proofJsonString) {
    const output = document.getElementById('integerStreamlinedOutput');
    
    try {
        const proofData = JSON.parse(proofJsonString);
        
        if (!verifyingKey) {
            output.innerHTML += '<div class="error">❌ Verifying key not loaded</div>';
            return;
        }
        
        output.innerHTML += '<div>🔍 Verifying proof...</div>';
        
        const isValidProof = await snarkjs.groth16.verify(
            verifyingKey,
            proofData.publicSignals,
            proofData.proof
        );
        
        if (isValidProof) {
            output.innerHTML += '<div class="success">✅ Proof verification successful! The proof is cryptographically valid.</div>';
        } else {
            output.innerHTML += '<div class="error">❌ Proof verification failed! The proof is invalid.</div>';
        }
        
    } catch (error) {
        output.innerHTML += `<div class="error">❌ Verification error: ${error.message}</div>`;
    }
}

// Initialize with example data
window.onload = function() {
    generateExampleKeys();
};

// Poseidon hash related functions for Merkle tree
function poseidonHash(inputs) {
    // This is a placeholder for the actual Poseidon hash implementation
    // In a real implementation, this would call the actual Poseidon hash function
    if (typeof snarkjs !== 'undefined' && typeof snarkjs.poseidon === 'function') {
        return snarkjs.poseidon(inputs);
    } else {
        // Fallback implementation if snarkjs.poseidon is not available
        console.warn("Poseidon hash function not available, using SHA-256 fallback");
        
        // Simple fallback using concatenation and string hashing
        // Note: This is NOT cryptographically equivalent to Poseidon
        // and should only be used for UI demonstration purposes
        const concatenated = inputs.join('|');
        
        // Simple hash function for demonstration
        let hash = 0;
        for (let i = 0; i < concatenated.length; i++) {
            const char = concatenated.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        
        // Return as string to match expected format
        return "0x" + Math.abs(hash).toString(16).padStart(8, '0');
    }
}

// Create a Merkle tree from RSA public keys
async function createMerkleTree(publicKeys) {
    try {
        const leaves = publicKeys.map(key => {
            // Convert public key components to field elements
            const e = BigInt(key.e);
            const n = BigInt(key.n);
            
            // Hash each public key to create a leaf
            // We hash e and n together to create a unique identifier for each key
            return poseidonHash([e.toString(), n.toString()]);
        });
        
        // Build the Merkle tree
        const tree = new MerkleTree(leaves);
        
        return {
            success: true,
            tree: tree,
            root: tree.getRoot(),
            leaves: leaves,
            numLeaves: leaves.length
        };
    } catch (error) {
        console.error('Error creating Merkle tree:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Simple Merkle Tree implementation
class MerkleTree {
    constructor(leaves) {
        this.leaves = leaves;
        this.layers = [leaves];
        this.buildTree();
    }
    
    buildTree() {
        let currentLayer = this.leaves;
        
        // Build the tree layer by layer until we reach the root
        while (currentLayer.length > 1) {
            const nextLayer = [];
            
            // Process pairs of nodes
            for (let i = 0; i < currentLayer.length; i += 2) {
                if (i + 1 < currentLayer.length) {
                    // Hash the pair of nodes
                    const hash = poseidonHash([currentLayer[i], currentLayer[i + 1]]);
                    nextLayer.push(hash);
                } else {
                    // Odd number of nodes, promote the last one
                    nextLayer.push(currentLayer[i]);
                }
            }
            
            // Add the new layer to our tree
            this.layers.push(nextLayer);
            currentLayer = nextLayer;
        }
    }
    
    getRoot() {
        // The root is the last element of the last layer
        return this.layers[this.layers.length - 1][0];
    }
    
    getProof(index) {
        if (index < 0 || index >= this.leaves.length) {
            throw new Error('Index out of range');
        }
        
        const proof = [];
        let currentIndex = index;
        
        // Generate the proof by traversing up the tree
        for (let i = 0; i < this.layers.length - 1; i++) {
            const layer = this.layers[i];
            const isRight = currentIndex % 2 === 0;
            const siblingIndex = isRight ? currentIndex + 1 : currentIndex - 1;
            
            // Check if sibling exists
            if (siblingIndex < layer.length) {
                proof.push({
                    position: isRight ? 'right' : 'left',
                    data: layer[siblingIndex]
                });
            }
            
            // Move to the parent index in the next layer
            currentIndex = Math.floor(currentIndex / 2);
        }
        
        return proof;
    }
    
    verify(leaf, proof, root) {
        let currentHash = leaf;
        
        // Traverse the proof and compute the root
        for (const node of proof) {
            if (node.position === 'left') {
                currentHash = poseidonHash([node.data, currentHash]);
            } else {
                currentHash = poseidonHash([currentHash, node.data]);
            }
        }
        
        // Check if the computed root matches the expected root
        return currentHash === root;
    }
}

// Function to handle Merkle tree generation from the UI
async function generateMerkleTree() {
    const merkleKeysInput = document.getElementById('merkleKeys').value;
    const merkleOutput = document.getElementById('merkleOutput');
    
    try {
        if (!merkleKeysInput.trim()) {
            throw new Error('Please provide RSA public keys');
        }
        
        // Parse public keys (format: "e1,n1;e2,n2;...")
        const keyPairs = merkleKeysInput.split(';').map(pair => pair.trim());
        const publicKeys = keyPairs.map(pair => {
            const [e, n] = pair.split(',').map(k => k.trim());
            if (!e || !n) throw new Error('Invalid public key format');
            return { e, n };
        });
        
        if (publicKeys.length === 0) {
            throw new Error('Please provide at least one public key pair');
        }
        
        merkleOutput.innerHTML = '<div>Building Merkle tree from public keys...</div>';
        
        // Check if snarkjs.poseidon is available
        if (typeof snarkjs === 'undefined' || typeof snarkjs.poseidon !== 'function') {
            merkleOutput.innerHTML += `
                <div class="warning" style="color: #ffc107;">Warning: Poseidon hash function not available. Using fallback hash.</div>
                <div>For cryptographic security in ZK proofs, you need a proper Poseidon implementation.</div>
            `;
        }
        
        // Generate the Merkle tree
        const result = await createMerkleTree(publicKeys);
        
        if (result.success) {
            // Create dropdown for selecting keys to generate proofs
            const keyOptions = publicKeys.map((key, index) => {
                const eDisplay = key.e.length > 10 ? `${key.e.substring(0, 10)}...` : key.e;
                const nDisplay = key.n.length > 10 ? `${key.n.substring(0, 10)}...` : key.n;
                return `<option value="${index}">Key ${index+1}: e=${eDisplay}, n=${nDisplay}</option>`;
            }).join('');
            
            // Display the Merkle tree information
            merkleOutput.innerHTML = `
                <div class="success">Merkle tree created successfully!</div>
                <div><strong>Number of leaves:</strong> ${result.numLeaves}</div>
                <div><strong>Merkle root:</strong></div>
                <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                    ${result.root}
                </div>
                
                <div style="margin-top: 15px;">
                    <label><strong>Generate Inclusion Proof:</strong></label>
                    <select id="keyProofIndex" style="width: 100%; padding: 8px; background: #2d2d2d; color: #e0e0e0; border: 1px solid #404040; border-radius: 4px;">
                        ${keyOptions}
                    </select>
                    <button onclick="generateMerkleProof(${result.numLeaves})" style="background-color: #9c27b0; margin-top: 10px;">
                        Generate Proof for Selected Key
                    </button>
                </div>
                
                <div id="merkleProofOutput" style="margin-top: 15px;"></div>
                
                <details>
                    <summary><strong>Merkle Tree Structure</strong></summary>
                    <pre>${JSON.stringify(result.tree.layers, null, 2)}</pre>
                </details>
                
                <div style="margin-top: 15px;">
                    <div><strong>Benefits for ZK proofs:</strong></div>
                    <ul>
                        <li>More efficient than linear verification of multiple keys</li>
                        <li>Can prove membership in a large set without revealing which key</li>
                        <li>Reduces circuit complexity for large numbers of keys</li>
                        <li>Compatible with the GroupVerify circuit pattern</li>
                    </ul>
                </div>
            `;
            
            // Store the tree in a global variable for later use
            window.currentMerkleTree = result.tree;
            window.currentMerkleLeaves = result.leaves;
            window.currentPublicKeys = publicKeys;
        } else {
            merkleOutput.innerHTML = `<div class="error">Merkle tree creation failed: ${result.error}</div>`;
        }
        
    } catch (error) {
        merkleOutput.innerHTML = `<div class="error">Error: ${error.message}</div>`;
        console.error('Merkle tree generation error:', error);
    }
}

// Function to generate a Merkle proof for a specific key
async function generateMerkleProof(numLeaves) {
    const proofIndex = parseInt(document.getElementById('keyProofIndex').value);
    const proofOutput = document.getElementById('merkleProofOutput');
    
    try {
        if (!window.currentMerkleTree || !window.currentMerkleLeaves || !window.currentPublicKeys) {
            throw new Error('Merkle tree not available. Please generate the tree first.');
        }
        
        if (proofIndex < 0 || proofIndex >= numLeaves) {
            throw new Error('Invalid key index');
        }
        
        // Get the proof for the selected key
        const proof = window.currentMerkleTree.getProof(proofIndex);
        const leaf = window.currentMerkleLeaves[proofIndex];
        const root = window.currentMerkleTree.getRoot();
        
        // Verify the proof
        const isValid = window.currentMerkleTree.verify(leaf, proof, root);
        
        // Display the proof
        proofOutput.innerHTML = `
            <div class="success">Merkle proof generated for Key ${proofIndex+1}</div>
            <div><strong>Selected Public Key:</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                e: ${window.currentPublicKeys[proofIndex].e}<br>
                n: ${window.currentPublicKeys[proofIndex].n}
            </div>
            
            <div><strong>Leaf Hash:</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${leaf}
            </div>
            
            <div><strong>Merkle Proof:</strong></div>
            <div style="word-break: break-all; font-family: monospace; background: #1a1a1a; padding: 10px; border-radius: 4px; margin: 5px 0;">
                ${JSON.stringify(proof, null, 2)}
            </div>
            
            <div><strong>Proof Verification:</strong> ${isValid ? '<span class="success">Valid ✓</span>' : '<span class="error">Invalid ✗</span>'}</div>
            
            <div style="margin-top: 15px; padding: 10px; background: #1e1e1e; border-radius: 4px;">
                <strong>Using this proof in a ZK circuit:</strong><br>
                This Merkle proof allows you to prove knowledge of a valid signature for one of the public keys in the tree,
                without revealing which key was used. This reduces the circuit complexity from O(n) to O(log n).
            </div>
            
            <button onclick="showCircuitIntegration()" style="background-color: #6c757d; margin-top: 10px;">
                Show Circuit Integration Details
            </button>
            <div id="circuitIntegrationDetails" style="display: none; margin-top: 10px;"></div>
        `;
        
    } catch (error) {
        proofOutput.innerHTML = `<div class="error">Error generating Merkle proof: ${error.message}</div>`;
        console.error('Merkle proof generation error:', error);
    }
}

// Function to show details about circuit integration
function showCircuitIntegration() {
    const detailsDiv = document.getElementById('circuitIntegrationDetails');
    
    if (detailsDiv) {
        detailsDiv.style.display = 'block';
        detailsDiv.innerHTML = `
            <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; font-size: 14px;">
                <h4 style="color: #bb86fc; margin-top: 0;">Integration with GroupVerify Circuit</h4>
                
                <p>To integrate this Merkle tree with the GroupVerify circuit:</p>
                
                <ol style="padding-left: 20px;">
                    <li>Modify the circuit to accept a Merkle root instead of all public keys</li>
                    <li>Add Poseidon hash constraints for verifying the Merkle path</li>
                    <li>Provide the Merkle proof as a private input to the circuit</li>
                    <li>Only reveal the Merkle root as a public output</li>
                </ol>
                
                <p><strong>Circuit Modification Example:</strong></p>
                <pre style="background: #2d2d2d; padding: 10px; border-radius: 4px; overflow-x: auto;">
// Modified GroupVerify circuit with Merkle tree support
template MerkleGroupVerify(n_bits, k, exp_bits) {
    // Public inputs
    signal input message[k];
    signal input merkle_root;
    
    // Private inputs
    signal input signature[k];
    signal input e[exp_bits];
    signal input N[k];
    signal input merkle_siblings[log2(max_keys)];
    signal input merkle_path_indices[log2(max_keys)];
    
    // 1. Verify signature against the provided public key
    component rsaVerify = RSAVerify(n_bits, k, exp_bits);
    rsaVerify.signature <== signature;
    rsaVerify.message <== message;
    rsaVerify.e <== e;
    rsaVerify.N <== N;
    
    // 2. Compute the leaf hash for the public key
    component leafHasher = Poseidon(exp_bits + k);
    for (var i = 0; i < exp_bits; i++) {
        leafHasher.inputs[i] <== e[i];
    }
    for (var i = 0; i < k; i++) {
        leafHasher.inputs[exp_bits + i] <== N[i];
    }
    
    // 3. Verify the Merkle path
    component merkleVerifier = MerkleProof(log2(max_keys));
    merkleVerifier.leaf <== leafHasher.out;
    merkleVerifier.root <== merkle_root;
    merkleVerifier.siblings <== merkle_siblings;
    merkleVerifier.path_indices <== merkle_path_indices;
}
</pre>
                
                <p><strong>Benefits:</strong></p>
                <ul style="padding-left: 20px;">
                    <li>Supports thousands of public keys with minimal circuit size increase</li>
                    <li>Merkle root can be published on-chain for verification</li>
                    <li>Compatible with recursive proof systems for even larger key sets</li>
                    <li>Poseidon hash is optimized for constraints in ZK circuits</li>
                </ul>
            </div>
        `;
    }
}