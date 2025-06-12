# Password Encryption Tool
Tools untuk mengamankan password dengan enkripsi AES-128 (Fernet)

Tools ini mengubah password yang tersimpan dalam file teks biasa (pwd.txt) menjadi terenkripsi secara otomatis, kemudian menghapus file aslinya untuk keamanan.

# 🛠 Fitur
✅ Enkripsi password menggunakan algoritma Fernet (AES-128)

✅ Pembuatan kunci enkripsi acak

✅ Penyimpanan kunci dan data terenkripsi terpisah

✅ Penghapusan otomatis file password asli

# ⚙️ Instalasi
Persyaratan Sistem
Python 3.6 atau lebih baru

Package `cryptography`

# Cara Install
```console
pip install cryptography
```
# Cara Penggunaan

1. Buat file password

Buat file bernama `pwd.txt` yang berisi password Anda:
```console
echo "password_rahasia_anda" > pwd.txt
```

