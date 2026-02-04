## SPHINCS Signature App
This project implements a desktop application for creating and verifying digital signatures using post-quantum cryptography based on the SPHINCS+ digital signature scheme. The application provides a graphical user interface that enables users to generate public and private key pairs, sign textual messages, and verify digital signatures using the corresponding public key. It demonstrates key concepts of modern cryptography, including public-key cryptography, hash-based signature schemes, message integrity, and resistance to quantum computing attacks while also illustrating the role of SHA-256 hashing. The system is implemented in C using the GTK framework and serves as an educational demonstration of integrating post-quantum cryptographic primitives into a practical desktop application.

## Instructions for Running the Application
1. Clone the repository or download it as a ZIP archive
2. Navigate to the project directory
3. Make sure all required dependencies are installed
4. Compile the project using the provided Makefile: `make`
5. Run the application: `./sphincs_app`

## Required Dependencies
- C compiler (GCC recommended)
- GTK development libraries
- OpenSSL (for cryptographic utilities if required by the environment)
- Linux-based operating system (recommended)
