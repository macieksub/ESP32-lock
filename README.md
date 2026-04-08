# Smart Lock ESP32 (University Project)

This is a simple ESP32-based smart lock project with keypad and web access.

## Project Overview

The system controls a door lock using a servo motor.  
Users can open the lock in two ways:
1. By entering a PIN on a 4x4 keypad
2. Through a local web panel after login

User accounts and permissions are stored in Firebase Realtime Database.

## Main Features

- PIN-based access from keypad
- Web login with USER/ADMIN roles
- Door open/close status in web panel
- Automatic lock close after a short delay
- Access logs saved to Firebase
- Emergency master PIN support
