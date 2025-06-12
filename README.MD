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

* Buat file bernama `pwd.txt` yang berisi password Anda:
```console
echo "password_rahasia_anda" > pwd.txt
```
* Eksekusi script Python:
```console
python CipherShield.py
```
Program akan menghasilkan:

* 🔑 `refKey.txt` - Kunci enkripsi (simpan dengan aman!)

* 🔒 `encryptedPWD.txt` - Password terenkripsi

* File pwd.txt akan terhapus otomatis

## ⚠️ Peringatan Keamanan
* Jangan simpan refKey.txt dan encryptedPWD.txt dalam folder yang sama

* Backup kunci enkripsi (refKey.txt) di lokasi aman

* Tanpa kunci enkripsi, password tidak bisa dikembalikan

## Untuk mendekripsi, Anda memerlukan:

* File `encryptedPWD.txt`

* File `refKey.txt`

* Script dekripsi (terpisah)

## ⚠️ Catatan:
Tools ini memberikan keamanan dasar. Untuk kebutuhan keamanan tinggi, pertimbangkan menggunakan password manager profesional.

[![GitHub](https://img.shields.io/badge/GitHub-View_Project-blue?logo=github)](https://github.com/hidayat-tanjung/enxcripty)

