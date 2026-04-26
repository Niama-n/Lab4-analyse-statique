from Crypto.Cipher import AES
import base64

def decrypt_vantage_point():
    key_hex = "8d127684cbc37c17616d806cf50473cc"
    key = bytes.fromhex(key_hex)
    data_b64 = "5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="
    ciphertext = base64.b64decode(data_b64)
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        padding_len = decrypted[-1]
        clean_text = decrypted[:-padding_len]
        print(f"Résultat décrypté : {clean_text.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"Erreur lors du décryptage : {e}")

if __name__ == "__main__":
    decrypt_vantage_point()