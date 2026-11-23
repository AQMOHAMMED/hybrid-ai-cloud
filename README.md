# Hybrid AI Trader — subscriber pages

Login + each subscriber's view-only dashboard (trades, wins, success rate, profit, open trades) and a "stop trading"
button that stops only his own bot. The trading PC pushes the numbers to `POST /sync` every few seconds and picks up
the stop clicks; nothing is stored on this server.

Deploy on Render (free): New → Web Service → this repo. Build `pip install -r requirements.txt`,
start `uvicorn app:app --host 0.0.0.0 --port $PORT`.
