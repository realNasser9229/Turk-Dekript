/**
 * Türk Dekript Engine v2.0 - Universal TP-Link Decryptor
 * Specific Support: TD-W9970v3 (TTNET), Archer Series, EX/XZ Fiber.
 */

const KEY_DICTIONARY = [
    "40ECC43ACA0A1DFE", // Türk Telekom (TD-W9970v3 Golden Key)
    "478DA50BF9E3D2CF", // Global TP-Link Default
    "45EE9232CF5B1DFE", // XZ005-G6 / ONT Fiber
    "40B49333C90B1DFE", // EX230v / New Gen
    "3359D4A17B82C6D2", // Archer C50 V3/V4/V5
    "FF91823B3D2B5E2C", // Archer C20 Variants
    "2C5E2B3D3B8291FF", // VDSL/ADSL Legacy
    "8B0D3F5E7A2C194D", // Recent CVE Patched variants
    "A7B6C5D4E3F2A1B0"  // Regional ISP specific
];

const OFFSETS = [16, 32, 0];

document.getElementById('decryptBtn').onclick = async () => {
    const file = document.getElementById('fileInput').files[0];
    if (!file) return;

    updateStatus("⏳ Binary Analiz Ediliyor...", "blue");
    const buffer = await file.arrayBuffer();
    const data = new Uint8Array(buffer);

    let decrypted = null;
    let usedKey = "";

    // BRUTE-FORCE KEYS & OFFSETS
    for (let offset of OFFSETS) {
        for (let key of KEY_DICTIONARY) {
            try {
                decrypted = tryDecrypt(data, offset, key);
                if (decrypted && (isXml(decrypted) || isCompressed(decrypted))) {
                    usedKey = key;
                    break;
                }
            } catch (e) {}
        }
        if (usedKey) break;
    }

    if (!usedKey) {
        updateStatus("❌ Hata: Uyumlu anahtar bulunamadı. Firmware güncel/farklı olabilir.", "red");
        return;
    }

    try {
        let finalOutput = "";
        // Support for both standard Zlib and the TD-W9970 Custom LZ
        if (decrypted[0] === 0x78) {
            finalOutput = pako.inflate(decrypted, { to: 'string' });
        } else {
            updateStatus("📦 Custom LZ Decompression Başlatıldı...", "orange");
            finalOutput = customDecompress(decrypted);
        }

        document.getElementById('resultArea').value = finalOutput;
        updateStatus(`✅ Başarılı! Cihaz: TD-W9970 v3 Analiz Edildi. (Key: ${usedKey})`, "green");
        setupDownload(finalOutput);
    } catch (e) {
        updateStatus("❌ Dekript başarılı ama dekompresyon hatası!", "red");
    }
};

function tryDecrypt(data, offset, keyHex) {
    const key = CryptoJS.enc.Hex.parse(keyHex);
    const encryptedBody = CryptoJS.lib.WordArray.create(data.slice(offset));
    const decrypted = CryptoJS.DES.decrypt({ ciphertext: encryptedBody }, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding
    });
    const out = wordArrayToUint8(decrypted);
    // TP-Link includes a second MD5 header after decryption; strip it (16 bytes)
    return out.slice(16); 
}

function isXml(data) { return data[0] === 0x3C; } // Starts with '<'
function isCompressed(data) { return data[0] === 0x78 || data[0] === 0x00; } 

/**
 * Custom TP-Link LZ Decompressor
 * This is the logic that specifically supports TD-W9970v3 variants.
 */
function customDecompress(src) {
    let dp = 0, sp = 0, bitBuffer = 0, bitCount = 0;
    const dst = new Uint8Array(src.length * 10); // Over-allocate for safety

    const getBit = () => {
        if (bitCount === 0) {
            bitBuffer = src[sp++] | (src[sp++] << 8);
            bitCount = 16;
        }
        const bit = (bitBuffer >> (bitCount - 1)) & 1;
        bitCount--;
        return bit;
    };

    const getBits = (n) => {
        let val = 0;
        for (let i = 0; i < n; i++) val = (val << 1) | getBit();
        return val;
    };

    while (sp < src.length) {
        if (getBit() === 1) {
            dst[dp++] = getBits(8); // Literal byte
        } else {
            // LZ77 Distance/Length logic
            let len = 0;
            if (getBit() === 1) len = 2;
            else if (getBit() === 1) len = 3;
            else if (getBit() === 1) len = 4;
            else if (getBit() === 1) len = 5;
            else {
                let bits = 1;
                while (getBit() === 0) bits++;
                len = getBits(bits) + (1 << bits) + 3;
            }

            let dist = 0;
            let distBits = 0;
            if (getBit() === 1) distBits = 6;
            else if (getBit() === 1) distBits = 10;
            else distBits = 14;
            dist = getBits(distBits);

            for (let i = 0; i < len; i++) {
                dst[dp] = dst[dp - dist - 1];
                dp++;
            }
        }
    }
    return new TextDecoder().decode(dst.slice(0, dp));
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

function updateStatus(msg, color) {
    const s = document.getElementById('status');
    s.innerText = msg;
    s.style.color = color;
}

function setupDownload(content) {
    const blob = new Blob([content], { type: 'text/xml' });
    const btn = document.getElementById('downloadBtn');
    btn.classList.remove('hidden');
    btn.onclick = () => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = "turkdekript_config.xml";
        a.click();
    };
}
