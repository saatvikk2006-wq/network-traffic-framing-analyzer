# FrameScope — Network Traffic Framing Analyzer Frontend

A responsive frontend for the Flask + Scapy backend for the BAITE203 Computer Networks and Data Communications Lab project.

## Project structure

```text
network-traffic-framing-analyzer-frontend/
├── index.html
├── styles.css
├── app.js
└── README.md
```

## Run locally

1. Start the backend first. From the backend folder, activate its virtual environment and run:

   ```bash
   python app.py
   ```

2. Keep the backend running at `http://127.0.0.1:5000`.

3. Open the frontend folder in VS Code and launch `index.html` with the **Live Server** extension. Alternatively, from the frontend folder run:

   ```bash
   python3 -m http.server 5500
   ```

   Then open `http://127.0.0.1:5500`.

4. Use **Load demo data**, upload a `.pcap` / `.pcapng` capture, paste hexadecimal frame bytes, or use live capture.

## API connection

The API base URL is set near the top of `app.js`:

```js
const API_BASE = "http://127.0.0.1:5000";
```

Change it only if the backend runs on a different host/port. The backend must allow CORS from the frontend origin.

## GitHub upload (Mac)

Extract the ZIP, then in Terminal navigate into the extracted folder. If it is in Downloads:

```bash
cd ~/Downloads/network-traffic-framing-analyzer-frontend
git init
git add .
git commit -m "Add FrameScope frontend"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/network-traffic-framing-analyzer-frontend.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username and use the exact repository URL from GitHub. If you have already initialized Git in this folder, do not run `git init` again; add, commit, and push your changes instead.

## Important notes

- The browser frontend requires the backend to be running for analysis features.
- Live capture permissions apply on the computer running the backend, not the browser.
- Do not upload sensitive capture files to public repositories. This frontend does not include capture files by default.
- GitHub Pages can host the static frontend, but `127.0.0.1` will refer to each visitor's own computer. For remote access, deploy the backend to a reachable server and update `API_BASE`.
