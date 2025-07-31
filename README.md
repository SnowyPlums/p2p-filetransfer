# P2P File Transfer

A peer-to-peer file transfer application that allows users to securely share files using WebRTC technology and Firebase for signaling.

## Features

- Direct peer-to-peer file transfer
- No file size limitations
- Secure end-to-end transfer
- Simple and intuitive interface
- Progress tracking for transfers
- No need to share ip's

## Prerequisites

- Python 3.8 or higher
- pip (Python Package Manager)
- A Firebase project

## Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project or select an existing one
3. Enable Realtime Database in your Firebase project
4. Go to Project Settings > Service Accounts
5. Generate a new private key (this will download a JSON file)
6. Place this file in the root directory of the project
7. Create a `.env` file in the root directory with:

```
FIREBASE_KEY_PATH=firebase-key.json
FIREBASE_DATABASE_URL=your-firebase-database-url
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/snowyplums/p2p-filetransfer.git
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

1. Run the application using Python:

```bash
python main.py
```

## Building Executable

To create a standalone executable that you can share with friends:

```bash
python build.py
```

The executable will be created in the `dist` directory. You can share this .exe file with others who can run it without needing Python installed.

## Usage

1. On the sender's device:

   - Click "Send File"
   - Select the file you want to send

2. On the recipient's device:
   - Wait for the connection to establish
   - The file transfer will begin automatically

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache-2.0 license - see the LICENSE file for details.
