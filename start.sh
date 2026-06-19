#!/usr/bin/env bash
# ==============================================================================
#  start.sh  --  run your app and get a public URL (via Cloudflare Tunnel)
#
#  SparkCloud spaces do NOT expose web ports to the internet directly, so to view
#  a web app you run it here and tunnel it out. This script starts your app, opens
#  a FREE Cloudflare "quick tunnel" to it, and prints a public
#  https://<something>.trycloudflare.com URL. Press Ctrl-C to stop -- it shuts down
#  both your app and the tunnel automatically.
#
#  >>> Easiest: ask Sparky  ->  "configure start.sh for my app"
#  >>> Or do it yourself: set PORT and APP_CMD below (uncomment one example), save,
#      then run:   ./start.sh        (first time:  chmod +x start.sh && ./start.sh)
# ==============================================================================

# ----- 1) CONFIGURE YOUR APP -- uncomment these two and edit -------------------
PORT=5000
APP_CMD="python main.py"

# ----- Examples by stack (copy one up to the two lines above, then tweak) ------
#   Node / Express:            PORT=3000 ; APP_CMD="node server.js"
#   npm script:                PORT=3000 ; APP_CMD="npm start"
#   Vite / React (dev):        PORT=5173 ; APP_CMD="npm run dev -- --host 0.0.0.0 --port 5173"
#   SvelteKit (dev):           PORT=5173 ; APP_CMD="npm run dev -- --host 0.0.0.0 --port 5173"
#   SvelteKit (adapter-node):  PORT=3000 ; APP_CMD="node build"          # after: npm run build
#   Next.js (dev):             PORT=3000 ; APP_CMD="npm run dev -- -p 3000"
#   Astro (dev):               PORT=4321 ; APP_CMD="npm run dev -- --host 0.0.0.0 --port 4321"
#   Flask:                     PORT=5000 ; APP_CMD="flask --app app run --host 0.0.0.0 --port 5000"
#   Django:                    PORT=8000 ; APP_CMD="python manage.py runserver 0.0.0.0:8000"
#   FastAPI / uvicorn:         PORT=8000 ; APP_CMD="uvicorn main:app --host 0.0.0.0 --port 8000"
#   Static folder:             PORT=8080 ; APP_CMD="python3 -m http.server 8080"
#   Go:                        PORT=8080 ; APP_CMD="go run ."
#   Ruby / Rails:              PORT=3000 ; APP_CMD="bin/rails server -b 0.0.0.0 -p 3000"
#   PHP:                       PORT=8000 ; APP_CMD="php -S 0.0.0.0:8000"
#
#  Tip: your app MUST listen on 0.0.0.0 (not just 127.0.0.1) and on $PORT.
# ------------------------------------------------------------------------------

set -uo pipefail

# ----- Ensure Python dependencies are installed (project venv) ---------------
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ] || [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "==> Creating Python virtualenv in $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi
if [ -f "requirements.txt" ]; then
  if ! "$VENV_DIR/bin/python" -c "import flask, flask_sqlalchemy, flask_cors, flask_limiter" >/dev/null 2>&1; then
    echo "==> Installing Python dependencies from requirements.txt into $VENV_DIR..."
    "$VENV_DIR/bin/pip" install --quiet -r requirements.txt
  fi
fi

# Make sure the app + cloudflared are reachable via the venv's PATH.
export PATH="$VENV_DIR/bin:$PATH"

if [ -z "${PORT:-}" ] || [ -z "${APP_CMD:-}" ]; then
  cat <<'MSG'
start.sh isn't configured yet.

Open start.sh and set PORT + APP_CMD (uncomment one of the examples near the top)
to match your app -- or just ask Sparky: "configure start.sh for my app".

Then run:   ./start.sh
MSG
  exit 1
fi

APP_PID=""
TUNNEL_PID=""
TUNNEL_LOG="$(mktemp)"

cleanup() {
  echo ""
  echo "==> Stopping app + tunnel..."
  [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" 2>/dev/null
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null
  pkill -P $$ 2>/dev/null
  rm -f "$TUNNEL_LOG" 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "==> Starting your app:  $APP_CMD   (expecting it on port $PORT)"
bash -c "$APP_CMD" &
APP_PID=$!

echo "==> Waiting for the app to listen on port $PORT..."
for _ in $(seq 1 40); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exec 3>&-; break; fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "ERROR: your app exited before binding port $PORT. Check APP_CMD and the logs above."
    exit 1
  fi
  sleep 1
done

echo "==> Opening Cloudflare tunnel..."
cloudflared tunnel --no-autoupdate --url "http://localhost:$PORT" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!

URL=""
for _ in $(seq 1 40); do
  URL="$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" | head -n1)"
  [ -n "$URL" ] && break
  sleep 1
done

echo ""
if [ -n "$URL" ]; then
  echo "============================================================"
  echo "  Your app is live at:   $URL"
  echo "============================================================"
  echo "  Press Ctrl-C to stop the app and tear down the tunnel."
else
  echo "WARNING: couldn't read a tunnel URL yet. Recent tunnel output:"
  tail -n 20 "$TUNNEL_LOG"
fi
echo ""

# Run until the app exits (or Ctrl-C triggers cleanup).
wait "$APP_PID"
