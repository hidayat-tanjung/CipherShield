flowchart TD
    A([Mulai]) --> B[[Tampilkan Banner ASCII]]
    B --> C[[Parse Argumen CLI]]
    C -->|Input Valid| D[[Verifikasi File Input]]
    C -->|Input Tidak Valid| E[[Tampilkan Bantuan]]
    D -->|File Ada| F[[Minta Passphrase]]
    D -->|File Tidak Ada| G[[Keluar dengan Error]]
    F --> H[[Verifikasi Passphrase]]
    H -->|Tidak Cocok| F
    H -->|Cocok| I[[Generate Salt]]
    I --> J[[Derive Key PBKDF2]]
    J --> K[[Baca File Input]]
    K --> L[[Enkripsi AES-128]]
    L --> M[[Tulis Output]]
    M --> N[[Hapus Aman File Asli]]
    N --> O[[Simpan Key File]]
    O --> P([Selesai])
    E --> Q([Keluar])
    G --> Q
