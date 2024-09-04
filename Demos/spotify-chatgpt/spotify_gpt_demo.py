# pip install requests python-dotenv querystring flask
import os
from dotenv import load_dotenv
import requests
import json
from base64 import b64encode
import random
import string
import base64
import requests
from urllib.parse import urlencode
from flask import Flask, request, redirect
import secrets

# Function to extract playlist ID from a playlist URL
def get_playlist_id(url):
    """Extract the playlist ID from the full URL."""
    return url.split("playlist/")[-1].split("?")[0]


# Function to authenticate with Spotify and get an access token
def get_access_token(client_id, client_secret):
    """Authenticate and retrieve access token using Spotify Client Credentials Flow.
    Documentation: https://developer.spotify.com/documentation/general/guides/authorization-guide/#client-credentials-flow
    """
    response = requests.post(
        "https://accounts.spotify.com/api/token",
        headers={
            "Authorization": "Basic "
            + b64encode(f"{client_id}:{client_secret}".encode()).decode()
        },
        data={"grant_type": "client_credentials"},
    )

    # Raises an HTTPError for bad requests
    response.raise_for_status()

    return response.json().get("access_token")

def get_user_access_token():
    return json.loads(open('spotify_token_data.json', 'r').read())['access_token']

# Function to fetch songs from a playlist
def fetch_songs_from_playlist(playlist_id, access_token, limit=10):
    """Fetch a list of songs from a specific Spotify playlist."""
    response = requests.get(
        f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
        # https://developer.spotify.com/documentation/web-api/concepts/access-token
        headers={"Authorization": f"Bearer {access_token}"},
        params={"limit": limit},
    )
    response.raise_for_status()
    return response.json()


# Function to interact with OpenAI's API to get song recommendations
def get_song_recommendation(songs_data, existing_songs_data, api_key):
    """Interact with OpenAI's API to get a song recommendation based on provided songs."""
    role_prompt = """
    You are going to recommend good music. You will respond exclusively with this exact template:
    {
        "name": "Song Name",
        "url": "Spotify Song URL"
    }
    You will be promptet by a list of songs already in the users playlist, as well
    as new songs for a different playlist. You should pick one that is not already
    in the users playlist and respond with the template.
    """
    songs_with_urls = [
        {
            "name": item["track"]["name"],
            "url": item["track"]["external_urls"]["spotify"],
        }
        for item in songs_data["items"]
    ]
    
    existing_song_names = [
        item["track"]["name"] for item in existing_songs_data["items"]
    ]
    
    prompt = f"""
    My existing songs are:
    {json.dumps(existing_song_names)}
    Now pick one of these:
    {json.dumps(songs_with_urls)}
    """

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": role_prompt},
                {"role": "user", "content": prompt},
            ],
        },
    )
    response.raise_for_status()
    
    suggestion = json.loads(response.json()["choices"][0]["message"]["content"])
    suggestion_url = suggestion["url"]
    # find it by external url
    for track in songs_data["items"]:
        if track["track"]["external_urls"]["spotify"] == suggestion_url:
            return track

    raise ValueError(f"Invalid song recommendation detected: {suggestion_url}")


# Function to add a song to a Spotify playlist
# https://developer.spotify.com/documentation/web-api/reference/add-tracks-to-playlist
def add_song_to_playlist(song, playlist_id, user_access_token):
    """Add a song to a Spotify playlist."""
    response = requests.post(
        f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
        headers={
            "Authorization": f"Bearer {user_access_token}",
            "Content-Type": "application/json",
        },
        json={
            "uris": [song['track']['uri']],
            "position": 0,
        },
    )
    
    response.raise_for_status()


# Function orchestrating the song recommendation process
def recommend():
    # Load environment variables from a .env file here
    load_dotenv()

    # Assign environment variables to Python variables
    source_playlist_url = os.getenv("SOURCE_PLAYLIST_URL")
    target_playlist_url = os.getenv("TARGET_PLAYLIST_URL")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")
    openai_api_key = os.getenv("OPENAI_API_KEY")

    source_playlist_id = get_playlist_id(source_playlist_url)
    target_playlist_id = get_playlist_id(target_playlist_url)

    access_token = get_access_token(client_id, client_secret)
    user_access_token = get_user_access_token()

    songs_data = fetch_songs_from_playlist(source_playlist_id, access_token)
    existing_target_songs_data = fetch_songs_from_playlist(target_playlist_id, access_token)

    recommended_song = get_song_recommendation(songs_data, existing_target_songs_data, openai_api_key)

    add_song_to_playlist(recommended_song, target_playlist_id, user_access_token)

    print(f"The recommended song is {recommended_song['track']['name']}")

def host_auth_endpoint():
    load_dotenv()
    
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")
    redirect_uri = os.getenv("REDIRECT_URI")

    app = Flask(__name__)

    @app.route('/login')
    def login():
        state = secrets.token_urlsafe(16)
        
        # What the app can do with the user's Spotify account
        # As a rule, in case you get hacked, only ask for what you need
        # https://developer.spotify.com/documentation/web-api/concepts/scopes
        scope = " ".join(
            [
                # Images
                # "ugc-image-upload",
                # Spotify Connect
                "user-read-playback-state",
                "user-modify-playback-state",
                "user-read-currently-playing",
                # Playback
                "app-remote-control",
                "streaming",
                # Playlists
                "playlist-read-private",
                "playlist-read-collaborative",
                "playlist-modify-private",
                "playlist-modify-public",
                # Follow
                # "user-follow-modify",
                # "user-follow-read",
                # Listening History
                "user-read-playback-position",
                "user-top-read",
                "user-read-recently-played",
                # Library
                "user-library-modify",
                "user-library-read",
                # Users
                # "user-read-email",
                # "user-read-private",
                # Open Access
                # "user-soa-link",
                # "user-soa-unlink",
                # "soa-manage-entitlements",
                # "soa-manage-partner",
                # "soa-create-partner",
            ]
        )
        
        
        
        spotify_login_url = 'https://accounts.spotify.com/authorize?' + urlencode({
            'response_type': 'code',
            'client_id': client_id,
            'scope': scope,
            'redirect_uri': redirect_uri,
            'state': state
        })
        
        return redirect(spotify_login_url)

    @app.route('/callback')
    def callback():
        global auth_options
        code = request.args.get('code', None)
        state = request.args.get('state', None)

        if state is None:
            return redirect('/#' + urlencode({'error': 'state_mismatch'}))
        else:
            auth_options = {
                'url': 'https://accounts.spotify.com/api/token',
                'form': {
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'grant_type': 'authorization_code'
                },
                'headers': {
                    'content-type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic ' + (base64.b64encode((client_id + ':' + client_secret).encode('utf-8'))).decode('utf-8')
                },
                'json': True
            }
            
            response = requests.post(auth_options['url'], data=auth_options['form'], headers=auth_options['headers'])
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Write token data to a JSON file
                token_data_file = 'spotify_token_data.json'
                with open(token_data_file, 'w') as f:
                    json.dump(token_data, f, indent=4)
                
                return ({"access_token": token_data}, 200)
            else:
                print("Failed to fetch access token. Error:", response.status_code)
                print(response.json())
                return ({"error": response.reason}, response.status_code)
            
            
                
    app.run(port=8080, host="0.0.0.0")

if __name__ == "__main__":
    recommend()
    # host_auth_endpoint()

