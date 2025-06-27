from flask import Flask, redirect, request, session, url_for, jsonify
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os

# Enable HTTP for local testing (OAuth normally requires HTTPS)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace this in production

CLIENT_SECRETS_FILE = "client_secret.json"

SCOPES = [
    "https://www.googleapis.com/auth/yt-analytics.readonly",
    "https://www.googleapis.com/auth/youtube.readonly"
]
REDIRECT_URI = "http://localhost:5000/oauth2callback"

def get_flow():
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

@app.route("/")
def index():
    if 'credentials' not in session:
        return '<a href="/login">Authorize with Google</a>'
    return '<a href="/analytics">Get YouTube Analytics</a> | <a href="/logout">Logout</a>'

@app.route("/login")
def login():
    flow = get_flow()
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = get_flow()
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for("index"))

@app.route("/analytics")
def analytics():
    if 'credentials' not in session:
        return redirect(url_for('login'))

    # channel_id = request.args.get("channel_id")
    # if not channel_id:
    #     return jsonify({"error": "Missing channel_id in request"}), 400

    creds_data = session['credentials']
    credentials = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )

    try:
        youtube = build("youtube", "v3", credentials=credentials)
        channels_response = youtube.channels().list(
            # part="snippet,statistics",
            # id=channel_id
            part="id",
            mine=True
        ).execute()

        print(channels_response, 'chennals list')
        channel_id = channels_response['items'][0]['id']

        analytics = build("youtubeAnalytics", "v2", credentials=credentials)
        report = analytics.reports().query(
            ids=f"channel=={channel_id}",
            startDate="2025-06-01",
            endDate="2025-06-27",
            metrics="views,estimatedMinutesWatched,averageViewDuration",
            dimensions="video",
            sort="-views",
            maxResults=50
        ).execute()
        
        
        return jsonify({
            "channel_id": channel_id,
            "report": report
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000 ,debug=True)
