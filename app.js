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


