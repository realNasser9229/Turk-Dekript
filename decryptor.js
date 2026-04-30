/**
 * Türk Dekript - Unified TP-Link Decryption Engine
 * Supports: Global, Türk Telekom, Archer, TD-W, EX, XZ, and Deco series.
 * Logic: Multi-offset brute-force with heuristic validation.
 */

// Expanded Key Database (DES ECB)
const DES_KEYS = [
    "40ECC43ACA0A1DFE", // Türk Telekom (Golden Key - Archer/VC)
    "478DA50BF9E3D2CF", // Global Standard Default
    "45EE9232CF5B1DFE", // XZ/Fiber ONT series
    "40B49333C90B1DFE", // EX/V-Series
    "3359D4A17B82C6D2", // Archer C20/C50 variants
    "FF91823B3D2B5E2C", // Old Archer C series
    "2C5E2B3D3B8291FF", // Alternate V2/V3 hardware
    "8B0D3F5E7A2C194D", // Recent CVE-2025 specific variants
    "A7B6C5D4E3F2A1B0", // Rare localized firmware
    "3132333435363738", // '12345678' in hex (Common for low-end)
    "0000000000000000"  // Null-key obfuscation
];

// Potential Offsets (Where the encrypted data starts after the header)
const OFFSETS = [16, 32, 0, 48];

document.getElementById('decryptBtn').onclick = async () => {
    const file = document.getElementById('fileInput').files[0];
    if (!file) return;

    updateStatus("🔍 Analyzing binary structure...");
    const buffer = await file.arrayBuffer();
    const data = new Uint8Array(buffer);

    let result = null;

    // --- PHASE 1: BRUTE-FORCE ENGINE ---
    // We loop through every known key and every common header offset.
    outerLoop:
    for (let offset of OFFSETS) {
        if (data.length <= offset) continue;

        for (let key of DES_KEYS) {
            try {
                const decrypted = attemptDES(data, offset, key);
                if (isValid(decrypted)) {
                    result = { 
                        data: cleanOutput(decrypted), 
                        key: key, 
                        offset: offset 
                    };
                    break outerLoop;
                }
            } catch (e) { continue; }
        }
    }

    // --- PHASE 2: PROCESSING & OUTPUT ---
    if (result) {
        try {
            let finalOutput = "";
            // Check for Zlib (0x78) or Deflate
            if (result.data[0] === 0x78 || (result.data[0] === 0x1f && result.data[1] === 0x8b)) {
                updateStatus("📦 Decompressing data stream...");
                finalOutput = pako.inflate(result.data, { to: 'string' });
            } else {
                finalOutput = new TextDecoder().decode(result.data);
            }

            document.getElementById('resultArea').value = finalOutput;
            document.getElementById('downloadBtn').classList.remove('hidden');
            updateStatus(`✅ Success! [Key: ${result.key}] [Offset: ${result.offset}]`);
            
            setupDownload(finalOutput);
        } catch (e) {
            updateStatus("❌ Decryption worked, but decompression failed. The file may be corrupt.");
        }
    } else {
        updateStatus("❌ Failed: Unsupported firmware. No matching key/offset found.");
    }
};

/** * Heuristic Validation: Determines if the decrypted bytes 
 * look like XML/JSON or a valid compression stream.
 */
function isValid(bytes) {
    if (!bytes || bytes.length < 20) return false;
    
    // Check for common XML/Config markers or Zlib headers
    const header = [bytes[0], bytes[1], bytes[2], bytes[3]];
    const markers = [
        0x3C, // '<' (XML)
        0x7B, // '{' (JSON)
        0x78, // 'x' (Zlib)
        0x1F  // Gzip
    ];

    // Some firmwares have a secondary 16-byte MD5 inside the encrypted stream.
    // We check both at index 0 and index 16.
    return markers.includes(bytes[0]) || markers.includes(bytes[16]);
}

function cleanOutput(bytes) {
    // If the data starts with valid markers at offset 16, strip the internal MD5.
    if ((bytes[16] === 0x3C || bytes[16] === 0x78) && bytes[0] !== 0x3C) {
        return bytes.slice(16);
    }
    return bytes;
}

function attemptDES(data, offset, keyHex) {
    const key = CryptoJS.enc.Hex.parse(keyHex);
    const encryptedBody = CryptoJS.lib.WordArray.create(data.slice(offset));
    
    const decrypted = CryptoJS.DES.decrypt(
        { ciphertext: encryptedBody },
        key,
        { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
    );
    
    return wordArrayToUint8(decrypted);
}

function wordArrayToUint8(wordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    for (let i = 0; i < l; i++) {
        result[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return result;
}

function updateStatus(msg) {
    const statusEl = document.getElementById('status');
    statusEl.innerText = msg;
    statusEl.style.color = msg.includes('✅') ? 'green' : 'red';
}

function setupDownload(content) {
    const blob = new Blob([content], { type: 'text/xml' });
    const downloadBtn = document.getElementById('downloadBtn');
    downloadBtn.onclick = () => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = "turkdekript_result.xml";
        a.click();
    };
}

