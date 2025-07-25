# WhiteAbyss – Secure File Sharing System

This repository contains the implementation of **WhiteAbyss**, a secure file sharing system developed as part of my internship project with the *Future Intern* program. The primary goal of this project is to explore the practical application of encryption, file integrity validation, and creating a basic user interface in a Flask-based web environment.

---

## Project Description

WhiteAbyss provides a web interface that allows users to securely upload and download files. All files are encrypted using AES (via Fernet) before being stored and are decrypted upon download. The system also includes SHA-256 checksum generation for file integrity validation.

---

## Key Features

- AES encryption for files at rest and in transit using Fernet
- SHA-256 checksum generation to verify file integrity
- Secure upload and download functionality via a web portal

---

## Technologies Used

- **Python Flask** – Web framework
- **Fernet (cryptography)** – AES encryption
- **HTML** – Frontend templating with Jinja2
- **dotenv** – Secure key handling via environment variables

---

## Project Structure

Whiteabyss_secure_file/
├── app.py
├── whiteabyss_uploads/
├── templates/
│ ├── index.html
├── .env
├── requirement.txt


---

## Setup Instructions

1. **Clone the repository:**

- git clone https://github.com/your-username/Future_Intern.git
- cd Future_Intern/future_cs_o2
2. **Create a virtual environment and activate it**:
- python -m venv venv
- source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install dependencies**:
- pip install -r requirements.tx
  
4. **Configure your .env file**:
- Create a .env file using the .env.example format and provide your AES key:
- This is the .env example format:
- SECRET_KEY=your_base64_aes_key_here
  
5. **Run the application**:
- python app.py
  
6. **Access the system**

## Reflections & Learning Outcomes
- Working on this project helped me understand:
- The importance of protecting sensitive data during transmission and storage.
- How encryption and integrity mechanisms like SHA-256 work in real applications.
- Building secure and functional Flask applications.

## Recommendations
- Based on the experience and lessons learned, the following recommendations are suggested for improving the system in future versions:
- **Implement Audit Logs**: Track and record every file access event (upload/download) with timestamps and user info to support accountability and incident investigation.
- **Store File Metadata in a Database**: Use SQLite or another lightweight database to store metadata such as filename, uploader name, upload date, file hash, and access logs.
- **Introduce Authentication & Access Control**: Require users to sign in before accessing file-related actions. This will help enforce role-based access and protect against unauthorized use.
- **Enable Real-Time Alerts**: Send email or dashboard alerts if an integrity check fails or if an unauthorized download attempt is detected.
- **Implement Role-Based Access Control (RBAC)**: Differentiate user roles (e.g., Admin, Uploader, Viewer) and assign permissions accordingly for tighter security and flexibility.


## Acknowledgements
This project was developed as part of a hands-on internship experience. I’m grateful for the guidance and opportunity to work on real-world security concepts and implement them in a meaningful way.


