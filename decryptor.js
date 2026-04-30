const KEYS = [
    "40ECC43ACA0A1DFE", // Türk Telekom Archer/VC series (Modern)
    "478DA50BF9E3D2CF", // Default Global TP-Link
    "45EE9232CF5B1DFE", // XZ series / Fiber ONT
    "40B49333C90B1DFE"  // EX series
];

const decryptBtn = document.getElementById('decryptBtn');
const fileInput = document.getElementById('fileInput');
const resultArea = document.getElementById('resultArea');
const status = document.getElementById('status');
const downloadBtn = document.getElementById('downloadBtn');

decryptBtn.onclick = async () => {
    if (!fileInput.files[0]) return;
    
    status.innerText = "Dekript ediliyor...";
    const buffer = await fileInput.files[0].arrayBuffer();
    const data = new Uint8Array(buffer);
    
    let decryptedData = null;
    let foundKey = "";

    // Iterate through known ISP keys
    for (const keyHex of KEYS) {
        try {
            decryptedData = performDecryption(data, keyHex);
            if (decryptedData) {
                foundKey = keyHex;
                break;
            }
        } catch (e) { continue; }
    }

    if (!decryptedData) {
        status.innerText = "Hata: Şifre çözülemedi. Geçersiz dosya veya bilinmeyen donanım yazılımı.";
        return;
    }

    try {
        let finalXml = "";
        // Check for Zlib compression header (0x78)
        if (decryptedData[0] === 0x78) {
            finalXml = pako.inflate(decryptedData, { to: 'string' });
        } else {
            finalXml = new TextDecoder().decode(decryptedData);
        }

        resultArea.value = finalXml;
        status.innerText = `Başarılı! (Anahtar: ${foundKey})`;
        downloadBtn.classList.remove('hidden');
        
        // Prepare download
        const blob = new Blob([finalXml], { type: 'text/xml' });
        downloadBtn.onclick = () => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = "decrypted_config.xml";
            a.click();
        };
    } catch (e) {
        status.innerText = "Dekript başarılı ancak sıkıştırma açılamadı.";
    }
};

function performDecryption(data, keyHex) {
    const key = CryptoJS.enc.Hex.parse(keyHex);
    // TP-Link files use 16-byte MD5 header. Skip it for decryption.
    const encryptedBody = CryptoJS.lib.WordArray.create(data.slice(16));
    
    const decrypted = CryptoJS.DES.decrypt(
        { ciphertext: encryptedBody },
        key,
        { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
    );

    const out = wordArrayToUint8(decrypted);
    
    // Validation: Standard TP-Link configs start with an internal MD5 or < (XML)
    // We strip the internal 16-byte header from the decrypted stream
    if (out[16] === 0x3C || out[16] === 0x78) {
        return out.slice(16);
    }
    return null;
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
