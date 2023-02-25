import os

import requests
import streamlit as st
from jose import JWTError, jwt

from dashboard.geos import geos
from dashboard.nextrad import nextrad
from dashboard.nextrad_stations import nextrad_stations

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM")

# PREFIX = "http://localhost:8000"
PREFIX = "http://fastapi:8000"


def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except:
        return None


def signup():
    st.title("Sign Up")
    username = st.text_input("Enter username")
    password = st.text_input("Enter password", type="password")
    if st.button("Sign up"):
        user = {"username": username, "password": password}
        response = requests.post(f"{PREFIX}/signup", json=user)

        if response.status_code == 200:
            user = response.json()
            st.success("You have successfully signed up!")
            st.write("Your username is:", user["username"])
        elif response.status_code == 400:
            st.error(response.json()["detail"])
        else:
            st.error("Something went wrong")


def signin():
    st.title("Sign In")
    username = st.text_input("Enter username")
    password = st.text_input("Enter password", type="password")

    if st.button("Sign in"):
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid profile email",
        }
        response = requests.post(
            f"{PREFIX}/signin",
            data=data,
            auth=("client_id", "client_secret"),
        )
        if response.status_code == 200:
            access_token = response.json()["access_token"]
            st.success("You have successfully signed in!")
            return access_token
        elif response.status_code == 400:
            st.error(response.json()["detail"])
        else:
            st.error("Something went wrong")


# Define the Streamlit pages
pages = {
    "GEOS": geos,
    "NEXTRAD": nextrad,
    "NEXTRAD STATIONS": nextrad_stations,
}


# Define the Streamlit app
def main():
    st.set_page_config(
        page_title="NOAA GOES Date", page_icon=":satellite:", layout="wide"
    )
    st.sidebar.title("Navigation")

    # Check if user is signed in
    token = st.session_state.get("token", None)
    user_id = decode_token(token)

    # Render the navigation sidebar
    if user_id is not None:
        selection = st.sidebar.radio("Go to", list(pages.keys()) + ["Log Out"])
    else:
        selection = st.sidebar.radio("Go to", ["Sign In", "Sign Up"])

    # Render the selected page or perform logout
    if selection == "Log Out":
        st.session_state.clear()
        st.sidebar.success("You have successfully logged out!")
        st.experimental_rerun()
    elif selection == "Sign In":
        token = signin()
        if token is not None:
            st.session_state.token = token
            print(token)
            st.experimental_rerun()
    elif selection == "Sign Up":
        signup()
    else:
        page = pages[selection]
        page(token)


if __name__ == "__main__":
    main()
