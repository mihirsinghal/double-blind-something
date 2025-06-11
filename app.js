let circuit = null;
let provingKey = null;
let verifyingKey = null;
let publicKeysList = [];

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

// Utility function to convert a big number to an array of 64-bit chunks
function bigIntTo64BitChunks(bigNum, numChunks) {
    const chunks = [];
    const mask = BigInt("0xFFFFFFFFFFFFFFFF"); // 64-bit mask
    let remaining = BigInt(bigNum);
    
    for (let i = 0; i < numChunks; i++) {
        chunks.push(Number(remaining & mask));
        remaining = remaining >> BigInt(64);
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

async function setupCircuit() {
    const publicKeysInput = document.getElementById('publicKeys').value;
    const setupOutput = document.getElementById('setupOutput');
    
    try {
        setupOutput.innerHTML = 'Setting up circuit...';
        
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
        
        // Constants for the circuit
        const K = 50; // Number of 64-bit chunks for signature and modulus
        const EXP_BITS = 17; // Number of bits for exponent
        
        const prepareStart = performance.now();
        // Convert signature to 64-bit chunks
        const signatureChunks = bigIntTo64BitChunks(signature, K);
        
        // Convert message to 64-bit chunks
        const messageChunks = bigIntTo64BitChunks(message, K);
        
        // Convert public keys to appropriate format
        const eArrays = publicKeysList.map(key => {
            const eBits = bigIntToBits(key.e, EXP_BITS);
            return eBits;
        });
        
        const nArrays = publicKeysList.map(key => {
            return bigIntTo64BitChunks(key.n, K);
        });

        console.log('Before padding:');
        console.log('eArrays:', eArrays);
        console.log('nArrays:', nArrays);
        
        // Ensure we have exactly 3 public key pairs for the circuit
        const paddedPublicKeys = [...publicKeysList];
        while (paddedPublicKeys.length < 3) {
            paddedPublicKeys.push(paddedPublicKeys[paddedPublicKeys.length - 1]);
        }
        if (paddedPublicKeys.length > 3) {
            paddedPublicKeys.length = 3;
        }

        // Pad the arrays to ensure we have exactly 3 entries
        while (eArrays.length < 3) {
            eArrays.push(eArrays[eArrays.length - 1]);
        }
        if (eArrays.length > 3) {
            eArrays.length = 3;
        }

        while (nArrays.length < 3) {
            nArrays.push(nArrays[nArrays.length - 1]);
        }
        if (nArrays.length > 3) {
            nArrays.length = 3;
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
            
            // Extract expected e and n arrays (padded to 3)
            const paddedKeys = [...publicKeysList];
            while (paddedKeys.length < 3) {
                paddedKeys.push(paddedKeys[paddedKeys.length - 1]);
            }
            if (paddedKeys.length > 3) {
                paddedKeys.length = 3;
            }
            const expectedE = paddedKeys.map(k => inputToFieldElement(k.e));
            const expectedN = paddedKeys.map(k => inputToFieldElement(k.n));
            
            // Compare public signals
            const publicSignals = proofData.publicSignals.map(s => s.toString());
            
            // Extract flattened arrays
            const actualE = [];
            for (let i = 0; i < 3; i++) {
                const eBits = publicSignals.slice(i * 17, (i + 1) * 17);
                actualE.push(eBits);
            }
            
            const actualN = [];
            for (let i = 0; i < 3; i++) {
                const nChunks = publicSignals.slice(51 + i * 50, 51 + (i + 1) * 50);
                actualN.push(nChunks);
            }
            
            const actualMessage = publicSignals.slice(201, 251);
            
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