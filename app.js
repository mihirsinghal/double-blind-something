let circuit = null;
let provingKey = null;
let verifyingKey = null;
let validHashesList = [];

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

async function setupCircuit() {
    const validHashesInput = document.getElementById('validHashes').value;
    const setupOutput = document.getElementById('setupOutput');
    
    try {
        setupOutput.innerHTML = 'Setting up circuit...';
        
        // Parse valid hashes (these should be poseidon hashes in string format)
        validHashesList = validHashesInput.split(',').map(h => h.trim());
        if (validHashesList.length === 0) {
            throw new Error('Please provide at least one valid hash');
        }
        
        // Load circuit files
        setupOutput.innerHTML = 'Loading circuit files...';
        
        try {
            // Load the compiled circuit
            const circuitResponse = await fetch('./poseidon_preimage_js/poseidon_preimage.wasm');
            if (!circuitResponse.ok) {
                throw new Error('Failed to load circuit WASM file. Make sure to run the setup first.');
            }
            circuit = await circuitResponse.arrayBuffer();
            
            // Load proving key
            const provingKeyResponse = await fetch('./poseidon_preimage_0000.zkey');
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
            <div>Valid hashes: ${validHashesList.length}</div>
            <div>Circuit loaded and ready to generate proofs</div>
            <div>Note: The circuit will verify that the preimage hashes to one of the provided valid hashes</div>
        `;
        
    } catch (error) {
        setupOutput.innerHTML = `<div class="error">Setup failed: ${error.message}</div>`;
    }
}

async function generateProof() {
    const preimage = document.getElementById('preimage').value;
    const proofOutput = document.getElementById('proofOutput');
    
    if (validHashesList.length === 0) {
        proofOutput.innerHTML = '<div class="error">Please setup the circuit first</div>';
        return;
    }
    
    if (!circuit || !provingKey) {
        proofOutput.innerHTML = '<div class="error">Circuit not loaded. Please run setup first.</div>';
        return;
    }
    
    try {
        proofOutput.innerHTML = 'Generating proof...';
        
        // Prepare circuit inputs
        const preimageForCircuit = inputToFieldElement(preimage);
        
        // Ensure we have exactly 5 valid hashes for the circuit
        const paddedValidHashes = [...validHashesList];
        while (paddedValidHashes.length < 5) {
            paddedValidHashes.push('0');
        }
        if (paddedValidHashes.length > 5) {
            paddedValidHashes.length = 5;
        }
        
        const circuitInputs = {
            preimage: preimageForCircuit,
            validHashes: paddedValidHashes
        };
        
        console.log('Circuit inputs:', circuitInputs);
        
        proofOutput.innerHTML = 'Computing witness and generating proof...';
        
        // Debug: check what's available in snarkjs
        console.log('snarkjs object:', snarkjs);
        console.log('snarkjs.groth16:', snarkjs.groth16);
        console.log('Available methods:', Object.keys(snarkjs));
        
        // Generate the full proof directly
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            circuitInputs,
            "./poseidon_preimage_js/poseidon_preimage.wasm",
            "./poseidon_preimage_0000.zkey"
        );
        
        const fullProof = {
            proof: proof,
            publicSignals: publicSignals
        };
        
        proofOutput.innerHTML = `
            <div class="success">Proof generated successfully!</div>
            <div><strong>Proof size:</strong> ${JSON.stringify(proof).length} bytes</div>
            <div><strong>Public signals:</strong> ${publicSignals.length}</div>
            <div><strong>Proof:</strong></div>
            <pre>${JSON.stringify(fullProof, null, 2)}</pre>
        `;
        
        // Auto-fill the verify section
        document.getElementById('proofJson').value = JSON.stringify(fullProof, null, 2);
        
    } catch (error) {
        proofOutput.innerHTML = `<div class="error">Proof generation failed: ${error.message}</div>`;
        console.error('Detailed error:', error);
    }
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
            // Additional check: verify that the public signals match our expected valid hashes
            const publicHashes = proofData.publicSignals.map(s => BigInt(s));
            const expectedHashes = validHashesList.map(h => BigInt(h));
            
            // Check if public signals match the valid hashes we set up
            const signalsMatch = publicHashes.length === expectedHashes.length &&
                publicHashes.every((hash, index) => hash === expectedHashes[index]);
            
            if (signalsMatch) {
                verifyOutput.innerHTML = `
                    <div class="success">✓ Proof verified successfully!</div>
                    <div>✓ Cryptographic proof is valid</div>
                    <div>✓ Public signals match expected valid hashes</div>
                    <div>The prover knows a preimage that hashes to one of the valid hashes without revealing the preimage.</div>
                    <div><strong>Public signals (valid hashes):</strong> ${proofData.publicSignals.length}</div>
                `;
            } else {
                verifyOutput.innerHTML = `
                    <div class="error">✗ Proof verification failed!</div>
                    <div>✓ Cryptographic proof is valid</div>
                    <div>✗ Public signals don't match expected valid hashes</div>
                    <div>The proof may be for a different set of valid hashes.</div>
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

// Helper function to generate some example hashes for testing
function generateExampleHashes() {
    // Placeholder values - you need to compute actual Poseidon hashes
    const exampleHashes = ['1', '2', '3', '4', '5'];
    
    document.getElementById('validHashes').value = exampleHashes.join(', ');
    console.log('Placeholder hashes loaded. You need to:');
    console.log('1. Compute actual Poseidon hashes for your preimages');
    console.log('2. Replace these placeholder values with real hashes');
    console.log('3. Use the corresponding preimage to generate the proof');
}

// Initialize with example data
window.onload = function() {
    generateExampleHashes();
};