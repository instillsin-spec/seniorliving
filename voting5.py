import os
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

import streamlit as st
from cryptography.fernet import Fernet


# =========================================================
# Streamlit configuration
# =========================================================

st.set_page_config(
    page_title="Secure Voting",
    page_icon="🗳️",
    layout="centered",
    initial_sidebar_state="collapsed",
)


# =========================================================
# Configuration
# =========================================================

DB_FILE = "voting.db"
OPTIONS = ["Yes", "No", "No Opinion"]

PHONE_HASH_SECRET_VALUE = os.environ.get("PHONE_HASH_SECRET")
ENCRYPTION_KEY_VALUE = os.environ.get("VOTE_ENCRYPTION_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not PHONE_HASH_SECRET_VALUE:
    st.error("PHONE_HASH_SECRET is not configured.")
    st.stop()

if not ENCRYPTION_KEY_VALUE:
    st.error("VOTE_ENCRYPTION_KEY is not configured.")
    st.stop()

if not ADMIN_PASSWORD:
    st.error("ADMIN_PASSWORD is not configured.")
    st.stop()

PHONE_HASH_SECRET = PHONE_HASH_SECRET_VALUE.encode("utf-8")

try:
    cipher = Fernet(ENCRYPTION_KEY_VALUE.encode("utf-8"))
except Exception:
    st.error("VOTE_ENCRYPTION_KEY is invalid.")
    st.stop()


# =========================================================
# Styling
# =========================================================

st.markdown(
    """
    <style>
        .block-container {
            max-width: 760px;
            padding: 1rem 0.8rem 3rem 0.8rem;
        }

        .app-header {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            color: white;
            padding: 1.5rem 1rem;
            border-radius: 18px;
            text-align: center;
            margin-bottom: 1rem;
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.25);
        }

        .app-header h1 {
            margin: 0;
            font-size: 1.8rem;
        }

        .app-header p {
            margin: 0.45rem 0 0;
            opacity: 0.9;
            font-size: 0.95rem;
        }

        .info-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 16px;
            padding: 1rem;
            margin: 0.7rem 0;
            line-height: 1.5;
        }

        .success-card {
            background: #ecfdf5;
            border: 1px solid #86efac;
            border-radius: 16px;
            padding: 1rem;
            color: #166534;
            margin: 0.7rem 0;
            line-height: 1.5;
        }

        .warning-card {
            background: #fffbeb;
            border: 1px solid #fcd34d;
            border-radius: 16px;
            padding: 1rem;
            color: #92400e;
            margin: 0.7rem 0;
            line-height: 1.5;
        }

        .stButton > button,
        .stFormSubmitButton > button {
            width: 100%;
            min-height: 3rem;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
        }

        input {
            border-radius: 10px !important;
        }

        div[role="radiogroup"] {
            gap: 0.5rem;
        }

        div[role="radiogroup"] label {
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 12px;
            padding: 0.7rem;
            width: 100%;
        }

        [data-testid="stMetric"] {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 0.8rem;
            border-radius: 14px;
        }

        @media (max-width: 600px) {
            .block-container {
                padding: 0.7rem 0.6rem 2rem 0.6rem;
            }

            .app-header h1 {
                font-size: 1.5rem;
            }

            div[role="radiogroup"] {
                flex-direction: column;
            }
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# Database
# =========================================================

def get_connection():
    connection = sqlite3.connect(
        DB_FILE,
        timeout=30,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS voters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_hash TEXT NOT NULL UNIQUE,
                encrypted_phone BLOB,
                voted INTEGER NOT NULL DEFAULT 0,
                registered_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ballots (
                id TEXT PRIMARY KEY,
                encrypted_vote BLOB NOT NULL,
                submitted_at TEXT NOT NULL
            )
            """
        )

        # Add encrypted_phone to older databases
        voter_columns = connection.execute(
            "PRAGMA table_info(voters)"
        ).fetchall()

        column_names = [
            column["name"]
            for column in voter_columns
        ]

        if "encrypted_phone" not in column_names:
            connection.execute(
                """
                ALTER TABLE voters
                ADD COLUMN encrypted_phone BLOB
                """
            )

        connection.commit()

    finally:
        connection.close()


# =========================================================
# Phone and security functions
# =========================================================

def normalize_phone(phone):
    phone = phone.strip()

    if phone.startswith("+"):
        return "+" + "".join(
            character
            for character in phone[1:]
            if character.isdigit()
        )

    return "".join(
        character
        for character in phone
        if character.isdigit()
    )


def valid_phone(phone):
    normalized = normalize_phone(phone)
    digits = normalized.replace("+", "")

    return (
        digits.isdigit()
        and len(digits) >= 7
        and len(digits) <= 15
    )


def hash_phone(phone):
    normalized = normalize_phone(phone)

    return hmac.new(
        PHONE_HASH_SECRET,
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def mask_phone(phone):
    if not phone:
        return "Unavailable"

    if len(phone) <= 4:
        return "*" * len(phone)

    return "*" * (len(phone) - 4) + phone[-4:]


# =========================================================
# Voter functions
# =========================================================

def register_phone(phone):
    normalized_phone = normalize_phone(phone)

    if not valid_phone(normalized_phone):
        return False, "Enter a valid mobile number."

    phone_hash = hash_phone(normalized_phone)

    encrypted_phone = cipher.encrypt(
        normalized_phone.encode("utf-8")
    )

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO voters (
                phone_hash,
                encrypted_phone,
                voted,
                registered_at
            )
            VALUES (?, ?, 0, ?)
            """,
            (
                phone_hash,
                encrypted_phone,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        connection.commit()
        return True, "Mobile number registered successfully."

    except sqlite3.IntegrityError:
        return False, "This mobile number is already registered."

    except Exception:
        return False, "The mobile number could not be registered."

    finally:
        connection.close()


def submit_vote(phone, selected_option):
    normalized_phone = normalize_phone(phone)

    if not valid_phone(normalized_phone):
        return False, "Enter a valid mobile number."

    if selected_option not in OPTIONS:
        return False, "Please select a valid voting option."

    phone_hash = hash_phone(normalized_phone)
    connection = get_connection()

    try:
        connection.execute("BEGIN IMMEDIATE")

        voter = connection.execute(
            """
            SELECT id, voted
            FROM voters
            WHERE phone_hash = ?
            """,
            (phone_hash,),
        ).fetchone()

        if voter is None:
            connection.rollback()
            return False, "This mobile number is not pre-registered."

        if voter["voted"] == 1:
            connection.rollback()
            return False, "This mobile number has already voted."

        encrypted_vote = cipher.encrypt(
            selected_option.encode("utf-8")
        )

        ballot_id = secrets.token_urlsafe(24)

        connection.execute(
            """
            INSERT INTO ballots (
                id,
                encrypted_vote,
                submitted_at
            )
            VALUES (?, ?, ?)
            """,
            (
                ballot_id,
                encrypted_vote,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        connection.execute(
            """
            UPDATE voters
            SET voted = 1
            WHERE id = ?
            """,
            (voter["id"],),
        )

        connection.commit()
        return True, "Your vote was submitted successfully."

    except Exception:
        connection.rollback()
        return False, "The vote could not be submitted."

    finally:
        connection.close()


# =========================================================
# Results and admin functions
# =========================================================

def decrypt_results():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT encrypted_vote
            FROM ballots
            """
        ).fetchall()

    finally:
        connection.close()

    results = {
        "Yes": 0,
        "No": 0,
        "No Opinion": 0,
    }

    for row in rows:
        try:
            vote = cipher.decrypt(
                row["encrypted_vote"]
            ).decode("utf-8")

            if vote in results:
                results[vote] += 1

        except Exception:
            continue

    return results


def get_voter_status():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                encrypted_phone,
                voted,
                registered_at
            FROM voters
            ORDER BY registered_at DESC
            """
        ).fetchall()

    finally:
        connection.close()

    voters = []

    for row in rows:
        phone = None

        if row["encrypted_phone"]:
            try:
                phone = cipher.decrypt(
                    row["encrypted_phone"]
                ).decode("utf-8")
            except Exception:
                phone = None

        voters.append(
            {
                "ID": row["id"],
                "Mobile number": phone,
                "Status": (
                    "Voted"
                    if row["voted"] == 1
                    else "Not voted"
                ),
                "Registered at": row["registered_at"],
            }
        )

    return voters


# =========================================================
# Start application
# =========================================================

initialize_database()

st.markdown(
    """
    <div class="app-header">
        <h1>🗳️ Secure Voting</h1>
        <p>Simple, private, and easy to use on mobile</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# Navigation
# =========================================================

view = st.radio(
    "Choose a section",
    [
        "🗳️ Cast Your Vote",
        "🔐 Administrator",
    ],
    horizontal=True,
)


# =========================================================
# Voter interface
# =========================================================

if view == "🗳️ Cast Your Vote":

    st.markdown(
        """
        <div class="info-card">
            <strong>How to vote</strong><br>
            Enter your pre-registered mobile number, select one answer,
            and press the submit button.
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("voting_form"):
        phone = st.text_input(
            "Pre-registered mobile number",
            type="password",
            placeholder="+15551234567",
            help="Enter the mobile number registered by the administrator.",
        )

        selected_option = st.radio(
            "Your answer",
            OPTIONS,
            index=None,
        )

        vote_submitted = st.form_submit_button(
            "Submit Vote",
            type="primary",
            use_container_width=True,
        )

    if vote_submitted:
        if not phone.strip():
            st.error("Enter your pre-registered mobile number.")

        elif selected_option is None:
            st.error("Please select Yes, No, or No Opinion.")

        else:
            success, message = submit_vote(
                phone,
                selected_option,
            )

            if success:
                st.markdown(
                    f"""
                    <div class="success-card">
                        <strong>✅ Vote submitted</strong><br>
                        {message}<br><br>
                        Your vote cannot be submitted again.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.error(message)


# =========================================================
# Administrator interface
# =========================================================

else:

    st.markdown(
        """
        <div class="warning-card">
            <strong>Administrator area</strong><br>
            Register voters, view vote totals, and see voter status.
        </div>
        """,
        unsafe_allow_html=True,
    )

    admin_password = st.text_input(
        "Administrator password",
        type="password",
        placeholder="Enter administrator password",
    )

    authenticated = False

    if admin_password:
        authenticated = secrets.compare_digest(
            admin_password,
            ADMIN_PASSWORD,
        )

        if not authenticated:
            st.error("Incorrect administrator password.")

    if authenticated:
        st.success("Administrator access granted.")

        st.divider()

        # -------------------------------------------------
        # Register voter
        # -------------------------------------------------

        st.subheader("📱 Register a mobile number")

        with st.form("registration_form"):
            admin_phone = st.text_input(
                "Mobile number",
                type="password",
                key="admin_phone",
                placeholder="+15551234567",
            )

            register_clicked = st.form_submit_button(
                "Register Mobile Number",
                type="primary",
                use_container_width=True,
            )

        if register_clicked:
            if not admin_phone.strip():
                st.error("Enter a mobile number.")
            else:
                success, message = register_phone(admin_phone)

                if success:
                    st.success(message)
                else:
                    st.warning(message)

        st.divider()

        # -------------------------------------------------
        # Vote totals
        # -------------------------------------------------

        st.subheader("📊 Vote totals")

        results = decrypt_results()
        total_votes = sum(results.values())

        st.metric(
            "Total votes",
            total_votes,
        )

        results_table = []

        for option, count in results.items():
            percentage = 0

            if total_votes > 0:
                percentage = count / total_votes * 100

            results_table.append(
                {
                    "Option": option,
                    "Votes": count,
                    "Percentage": f"{percentage:.1f}%",
                }
            )

        st.table(results_table)

        if total_votes > 0:
            st.bar_chart(results)
        else:
            st.info("No votes have been submitted yet.")

        st.divider()

        # -------------------------------------------------
        # Voter status
        # -------------------------------------------------

        st.subheader("👥 Voter status")

        st.write(
            "This table shows which registered voters have submitted a ballot."
        )

        show_full_numbers = st.checkbox(
            "Show full mobile numbers",
            value=False,
        )

        voters = get_voter_status()

        display_rows = []

        for voter in voters:
            phone = voter["Mobile number"]

            if show_full_numbers:
                displayed_phone = phone or "Unavailable"
            else:
                displayed_phone = mask_phone(phone)

            display_rows.append(
                {
                    "ID": voter["ID"],
                    "Mobile number": displayed_phone,
                    "Status": voter["Status"],
                    "Registered at": voter["Registered at"],
                }
            )

        if display_rows:
            st.dataframe(
                display_rows,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No voters have been registered yet.")

