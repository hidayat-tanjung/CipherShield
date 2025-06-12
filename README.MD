%% SPET Workflow Diagram
flowchart TD
    A([Start]) --> B[Display ASCII Banner]
    B --> C{Parse Command\nLine Arguments}
    C -->|Valid Input| D[Verify Input File Exists]
    C -->|Invalid Input| E[Show Help & Exit]
    D --> F[Get Encryption Passphrase\n(Min 12 chars)]
    F --> G[Verify Passphrase Match]
    G -->|No Match| F
    G -->|Match| H[Generate Random Salt]
    H --> I[Derive Fernet Key\n(PBKDF2-SHA256)]
    I --> J[Read Input File]
    J --> K[Encrypt Data\n(AES-128-CBC)]
    K --> L[Write Output:\nSalt + Encrypted Data]
    L --> M[Securely Wipe\nOriginal File]
    M --> N[Save Key File]
    N --> O([Success])
    D -->|File Not Found| P[Error & Exit]
