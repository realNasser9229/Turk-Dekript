/**
 * Türk Dekript Engine v3.0 - Root Escalator Edition
 * Includes Decryption, Escelation, Compression, and Re-encryption with MD5 Checksumming.
 */

const KEY_DICTIONARY = [
    "40ECC43ACA0A1DFE", // Türk Telekom (TD-W9970v3 Golden Key)
    "478DA50BF9E3D2CF", // Global TP-Link Default
    "45EE9232CF5B1DFE", // XZ005-G6
    "40B49333C90B1DFE", // EX230v
    "3359D4A17B82C6D2", // Archer C50
    "FF91823B3D2B5E2C"  // Archer C20
];

const OFFSETS = [16, 32, 0];
let ACTIVE_KEY = "";
let ORIG_IS_ZLIB = false;

// --- CORE UI BINDINGS ---
document.getElementById('decryptBtn').onclick = processDecryption;
document.getElementById('escalateBtn').onclick = injectRootPrivileges;
document.getElementById('encryptBtn').onclick = processEncryption;

// --- DECRYPTION ENGINE ---
async function processDecryption() {
    const file = document.getElementById('fileInput').files[0];
    if (!file) return;

    updateStatus("Binary Analiz Ediliyor...", "status-blue");
    const buffer = await file.arrayBuffer();
    const data = new Uint8Array(buffer);

    let decrypted = null;
    ACTIVE_KEY = "";

    for (let offset of OFFSETS) {
        for (let key of KEY_DICTIONARY) {
            try {
                decrypted = tryDecrypt(data, offset, key);
                if (decrypted && (isXml(decrypted) || isCompressed(decrypted))) {
                    ACTIVE_KEY = key;
                    break;
                }
            } catch (e) {}
        }
        if (ACTIVE_KEY) break;
    }

    if (!ACTIVE_KEY) {
        updateStatus("Hata: Uyumlu anahtar bulunamadı.", "status-red");
        return;
    }

    try {
        let finalOutput = "";
        if (decrypted[0] === 0x78) {
            ORIG_IS_ZLIB = true;
            finalOutput = pako.inflate(decrypted, { to: 'string' });
        } else {
            ORIG_IS_ZLIB = false;
            finalOutput = customDecompress(decrypted);
        }

        document.getElementById('resultArea').value = finalOutput;
        updateStatus(`Cihaz Analiz Edildi. (Key: ${ACTIVE_KEY})`, "status-green");
        
        // Unlock next stages
        document.getElementById('escalateBtn').disabled = false;
        document.getElementById('encryptBtn').disabled = false;
    } catch (e) {
        updateStatus("Deşifre başarılı ama dekompresyon hatası!", "status-red");
    }
}

// --- ROOT ESCALATION ENGINE ---
function injectRootPrivileges() {
    const xmlString = document.getElementById('resultArea').value;
    if (!xmlString) return;

    try {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, "text/xml");

        // 1. Force Admin Levels
        const userNodes = xmlDoc.getElementsByTagName('User');
        let modifications = 0;
        for (let i = 0; i < userNodes.length; i++) {
            let user = userNodes[i];
            if (user.getAttribute('Level') !== '0') {
                user.setAttribute('Level', '0'); // 0 = SuperAdmin in TP-Link
                user.setAttribute('Privilege', '1');
                modifications++;
            }
        }

        // 2. Unhide Telnet/SSH
        const sshNodes = xmlDoc.getElementsByTagName('SSH');
        const telnetNodes = xmlDoc.getElementsByTagName('Telnet');
        [...sshNodes, ...telnetNodes].forEach(node => {
            if(node.getAttribute('Enable') !== '1') {
                node.setAttribute('Enable', '1');
                modifications++;
            }
        });

        const serializer = new XMLSerializer();
        let newXml = serializer.serializeToString(xmlDoc);
        
        // TP-Link XMLs often require a specific header
        if (!newXml.startsWith('<?xml')) {
            newXml = '<?xml version="1.0"?>\r\n' + newXml;
        }

        document.getElementById('resultArea').value = newXml;
        updateStatus(`Root Enjekte Edildi. (${modifications} yetki seviyesi değiştirildi)`, "status-blue");
        
    } catch (err) {
        updateStatus("XML Ayrıştırma Hatası!", "status-red");
    }
}

// --- ENCRYPTION & PACKAGING ENGINE ---
function processEncryption() {
    if (!ACTIVE_KEY) return;
    
    updateStatus("Paketleniyor...", "status-blue");
    const xmlData = document.getElementById('resultArea').value;
    
    // 1. Compress
    let compressed;
    if (ORIG_IS_ZLIB) {
        compressed = pako.deflate(xmlData);
    } else {
        // Fallback: If custom LZ was used, TP-Link restore functions usually 
        // still accept standard Zlib deflate as long as the 0x78 header is present.
        compressed = pako.deflate(xmlData); 
    }

    // 2. Pad for DES-ECB (Block size 8)
    const paddingLength = 8 - (compressed.length % 8);
    const padded = new Uint8Array(compressed.length + paddingLength);
    padded.set(compressed);
    // Add PKCS7 style padding
    for(let i = compressed.length; i < padded.length; i++) padded[i] = paddingLength;

    // 3. Encrypt
    const key = CryptoJS.enc.Hex.parse(ACTIVE_KEY);
    const words = [];
    for (let i = 0; i < padded.length; i += 4) {
        words.push((padded[i]<<24) | (padded[i+1]<<16) | (padded[i+2]<<8) | padded[i+3]);
    }
    const wordArray = CryptoJS.lib.WordArray.create(words, padded.length);
    
    const encrypted = CryptoJS.DES.encrypt(wordArray, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding
    });

    // 4. Calculate MD5 for the TP-Link Header
    const md5Hash = CryptoJS.MD5(encrypted.ciphertext);
    
    // 5. Build Final Binary (16 byte MD5 + Encrypted Payload)
    const finalPayloadSize = 16 + encrypted.ciphertext.sigBytes;
    const finalBin = new Uint8Array(finalPayloadSize);
    
    // Inject MD5 Header
    const md5Words = md5Hash.words;
    for (let i = 0; i < 4; i++) {
        finalBin[i*4]   = (md5Words[i] >>> 24) & 0xff;
        finalBin[i*4+1] = (md5Words[i] >>> 16) & 0xff;
        finalBin[i*4+2] = (md5Words[i] >>> 8) & 0xff;
        finalBin[i*4+3] = md5Words[i] & 0xff;
    }
    
    // Inject Ciphertext
    const cipherWords = encrypted.ciphertext.words;
    let offset = 16;
    for (let i = 0; i < encrypted.ciphertext.sigBytes / 4; i++) {
        finalBin[offset++] = (cipherWords[i] >>> 24) & 0xff;
        finalBin[offset++] = (cipherWords[i] >>> 16) & 0xff;
        finalBin[offset++] = (cipherWords[i] >>> 8) & 0xff;
        finalBin[offset++] = cipherWords[i] & 0xff;
    }

    // 6. Download Trigger
    const blob = new Blob([finalBin], { type: 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = "conf_escalated.bin";
    a.click();
    
    updateStatus("Şifreleme Başarılı! İndiriliyor...", "status-green");
}

// --- UTILITIES ---
function tryDecrypt(data, offset, keyHex) {
    const key = CryptoJS.enc.Hex.parse(keyHex);
    const encryptedBody = CryptoJS.lib.WordArray.create(data.slice(offset));
    const decrypted = CryptoJS.DES.decrypt({ ciphertext: encryptedBody }, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding
    });
    const out = wordArrayToUint8(decrypted);
    return out.slice(16); // Strip internal MD5
}

function isXml(data) { return data[0] === 0x3C; }
function isCompressed(data) { return data[0] === 0x78 || data[0] === 0x00; }

function wordArrayToUint8(wordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    for (let i = 0; i < l; i++) {
        result[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return result;
}

function updateStatus(msg, className) {
    const s = document.getElementById('status');
    s.innerText = msg;
    s.className = "status-msg " + className;
}

// Legacy custom decompressor included from previous version
function customDecompress(src) {
    let dp = 0, sp = 0, bitBuffer = 0, bitCount = 0;
    const dst = new Uint8Array(src.length * 10);
    const getBit = () => {
        if (bitCount === 0) { bitBuffer = src[sp++] | (src[sp++] << 8); bitCount = 16; }
        const bit = (bitBuffer >> (bitCount - 1)) & 1;
        bitCount--; return bit;
    };
    const getBits = (n) => { let val = 0; for (let i = 0; i < n; i++) val = (val << 1) | getBit(); return val; };

    while (sp < src.length) {
        if (getBit() === 1) dst[dp++] = getBits(8);
        else {
            let len = 0;
            if (getBit() === 1) len = 2; else if (getBit() === 1) len = 3;
            else if (getBit() === 1) len = 4; else if (getBit() === 1) len = 5;
            else { let bits = 1; while (getBit() === 0) bits++; len = getBits(bits) + (1 << bits) + 3; }
            let distBits = 0;
            if (getBit() === 1) distBits = 6; else if (getBit() === 1) distBits = 10; else distBits = 14;
            let dist = getBits(distBits);
            for (let i = 0; i < len; i++) { dst[dp] = dst[dp - dist - 1]; dp++; }
        }
    }
    return new TextDecoder().decode(dst.slice(0, dp));
}
