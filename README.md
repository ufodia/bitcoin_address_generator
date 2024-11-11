
# Bitcoin Address Generator

This Python script is a comprehensive tool that creates various types of Bitcoin addresses, including P2PKH, P2SH, Bech32, and P2SH-P2WPKH formats. It allows users to input either a plain text sentence or a hexadecimal string, converting these inputs into private and public keys and subsequently generating the respective Bitcoin addresses.

## Features

- **Multiple Address Formats**: Generate Bitcoin addresses in P2PKH, P2SH, Bech32, and P2SH-P2WPKH formats.
- **Key Compression**: Supports both compressed and uncompressed public keys.
- **Input Flexibility**: Accepts plain text or hexadecimal strings for private key generation.
- **Wallet Import Format**: Displays Bitcoin addresses along with their respective WIF keys.
- **Balance Check**: Integrates with Blockchain.info API to check the balance of generated addresses.

## Prerequisites

Before starting, ensure you have the following installed:
- **Python 3.x**: [Download Python](https://www.python.org/downloads/)
- **pip**: Typically included with Python.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/bitcoin-address-generator.git
   
2. **Navigate to the project directory**:
   ```bash
    cd bitcoin-address-generator

3. **Install required packages**:
    ```bash  
    pip install -r requirements.txt

## Usage
  Run the address generator using the following command:
  
    
    python brain-hex to wif -balance.py
  
  Follow the on-screen prompts to enter your input and generate Bitcoin addresses.

## Building an Executable
Convert this script into a standalone executable for Windows with **auto-py-to-exe**:

  1. **Install auto-py-to-exe**:
      ```bash
      pip install auto-py-to-exe
  
  2. **Launch the GUI**:
      ```bash
      auto-py-to-exe
  
  3. **Configure and build**:
  Follow the GUI instructions to select your script, choose the output directory, and configure executable settings.

## Contributing
Contributions are very welcome! Please open an issue first to discuss what you would like to change or submit a pull request with your suggestions.


## Acknowledgments
Thanks to the developers of the ecdsa and base58 Python libraries.
Utilizes Blockchain.info APIs for fetching address balances.

## Donate
Support this project by sending Bitcoin donations to the address below:

**BTC**: `1GZdNtQYa2DN4b3hLekrYErv9c8WLqbBTm`

Thank you for your support!
