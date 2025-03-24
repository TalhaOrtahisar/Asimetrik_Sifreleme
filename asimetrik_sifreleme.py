from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# RSA anahtar çiftini oluştur
def anahtar_olustur():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

# Mesajı şifrele
def mesaj_sifrele(public_key, mesaj):
    ciphertext = public_key.encrypt(
        mesaj.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Şifreli mesajı çöz
def mesaj_coz(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Anahtarları oluştur
private_key, public_key = anahtar_olustur()

# Mesaj
mesaj = "Bu kod asimetrik şifreleme yöntemi yapılamsı için yazılmıştır."

# Mesajı şifrele
sifreli_mesaj = mesaj_sifrele(public_key, mesaj)
print("Şifreli Mesaj:", sifreli_mesaj)

# Mesajı çöz
cozulmus_mesaj = mesaj_coz(private_key, sifreli_mesaj)
print("Çözülmüş Mesaj:", cozulmus_mesaj)
