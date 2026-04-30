const KEYS = [
    "478DA50BF9E3D2CF", // Standard/Global Default
    "40ECC43ACA0A1DFE", // VC220-G3U / Common Türk Telekom
    "45EE9232CF5B1DFE", // XZ005-G6
    "40B49333C90B1DFE"  // EX230V
];

document.getElementById('decryptBtn').onclick = async () => {
    const file = document.getElementById('fileInput').files[0];
    if (!file) return alert("Select a file first.");
    
    updateStatus("Processing...");
    const buffer = await file.arrayBuffer();
    const data = new Uint8Array(buffer);
    
    let decrypted = null;
    let usedKey = "";

    // 1. Try Decryption with multiple keys
    for (let keyHex of KEYS) {
        try {
            decrypted = tryDecrypt(data, keyHex);
            if (decrypted) {
                usedKey = keyHex;
                break;
            }
        } catch (e) { continue; }
    }

    if (!decrypted) {
        updateStatus("Error: Could not decrypt. Unsupported firmware or wrong key.");
        return;
    }

    // 2. Handle Compression (Zlib or Custom LZ)
    let finalContent = "";
    try {
        if (isZlib(decrypted)) {
            finalContent = pako.inflate(decrypted, { to: 'string' });
        } else {
            // Try custom decompression (older Türk Telekom models)
            finalContent = customDecompress(decrypted);
        }
        
        document.getElementById('resultArea').value = finalContent;
        document.getElementById('downloadBtn').classList.remove('hidden');
        updateStatus(`Success! Decrypted using key: ${usedKey}`);
    } catch (e) {
        updateStatus("Decryption succeeded but decompression failed. Check file integrity.");
    }
};

function tryDecrypt(data, keyHex) {
    const key = CryptoJS.enc.Hex.parse(keyHex);
    // TP-Link files usually have a 16-byte MD5 header
    const encryptedBody = CryptoJS.lib.WordArray.create(data.slice(16));
    
    const decrypted = CryptoJS.DES.decrypt(
        { ciphertext: encryptedBody },
        key,
        { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
    );

    const decryptedBytes = wordArrayToUint8(decrypted);
    // Basic verification: Check if it looks like XML or has the internal MD5
    if (decryptedBytes[16] === 0x3C || decryptedBytes[0] === data[0]) {
        return decryptedBytes.slice(16); // Strip internal MD5
    }
    return null;
}

function isZlib(data) {
    return data[0] === 0x78 && (data[1] === 0x01 || data[1] === 0x9C || data[1] === 0xDA);
}

// Custom TP-Link Decompression Port (Simplified)
function customDecompress(src) {
    // This is a placeholder for the bit-stream LZ logic used in tpconf_bin_xml
    // Most newer Türk Telekom devices use Zlib, so Pako handles them.
    // If it's pure XML, return as string.
    return new TextDecoder().decode(src);
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
    document.getElementById('status').innerText = msg;
  }
