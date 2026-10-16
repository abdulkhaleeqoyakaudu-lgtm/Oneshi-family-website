# ONESHI FAMILY — ready-to-open Windows package

## Start the website
1. Extract this ZIP completely into a folder on your Windows computer.
2. Make sure Node.js 20 or newer is installed.
3. Double-click `start-windows.bat`.
4. On first launch, it installs the required packages (internet connection required).
5. It starts the local website and opens the administrator login page at http://localhost:3000/admin.

## Configured local administrator
- Email: abdulkhaliqoyakaudu@gmail.com
- Password: the password provided for this local package

The email is prefilled on the login page. Enter the password to sign in. The application intentionally retains the login step rather than bypassing authentication.

## Important
- This is a local Windows application, not a website published on the internet.
- Keep `.env` private. Do not upload it publicly or share it.
- The requested password is short and weak. Change it to a long unique password before using the dashboard with real family data. Because this package synchronizes the configured administrator password when the server starts, update `ADMIN_PASSWORD` in `.env` if you change it.
- Back up the `data` folder. It contains the local database and family-tree data.
- Keep the server terminal window open while using the site. Closing it stops the website.
