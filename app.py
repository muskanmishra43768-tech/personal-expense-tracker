import os
import random
import hmac
import requests
from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from database import get_connection, create_tables


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__, template_folder="templates")

app.secret_key = os.getenv(
    "SECRET_KEY",
    "personal-expense-tracker-dev-secret-key"
)


# =========================================================
# EMAIL SETTINGS
# =========================================================

GOOGLE_APPS_SCRIPT_URL = os.getenv("GOOGLE_APPS_SCRIPT_URL", "").strip()

# =========================================================
# ADMIN SETTINGS
# =========================================================

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_current_user():
    """
    Returns the currently logged-in user's database row.
    Returns None if no user is logged in.
    """

    user_id = session.get("user_id")

    if not user_id:
        return None

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT id, full_name, mobile, email, is_verified, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        return user

    finally:
        connection.close()


def send_otp_email(email, otp):
    """Send OTP via the Google Apps Script HTTPS web app."""
    if not GOOGLE_APPS_SCRIPT_URL:
        print("EMAIL ERROR: GOOGLE_APPS_SCRIPT_URL is missing.")
        return False

    try:
        response = requests.post(
            GOOGLE_APPS_SCRIPT_URL,
            json={
                "email": email,
                "otp": otp,
                "purpose": "Personal Expense Tracker OTP",
                "valid_minutes": 10
            },
            timeout=25
        )
        print("Apps Script email response:", response.status_code, response.text[:300])
        if not response.ok:
            return False
        try:
            payload = response.json()
            return payload.get("success") is True
        except ValueError:
            # Apps Script may return a redirect/html response even after accepting a POST.
            # Do not claim success unless its response explicitly confirms it.
            return False
    except Exception as error:
        print("EMAIL ERROR:", repr(error))
        return False


def create_and_send_otp(user_id, email, purpose="signup"):
    """
    Creates a 6-digit OTP and stores it in database.
    """

    otp = str(
        random.randint(
            100000,
            999999
        )
    )

    expires_at = (
        datetime.now() +
        timedelta(minutes=10)
    ).isoformat()

    connection = get_connection()

    try:

        connection.execute(
            """
            INSERT INTO otp_verifications
            (
                user_id,
                otp_code,
                purpose,
                expires_at,
                is_used,
                created_at
            )
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (
                user_id,
                otp,
                purpose,
                expires_at,
                datetime.now().isoformat()
            )
        )

        connection.commit()

    finally:

        connection.close()

    email_sent = send_otp_email(
        email,
        otp
    )

    return email_sent


# =========================================================
# ACTIVITY LOG HELPER
# =========================================================

def log_activity(user_id, action, details=""):
    """Stores a user/admin activity in the activity_logs table."""

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO activity_logs
            (user_id, action, details, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                user_id,
                action,
                details,
                datetime.now().isoformat()
            )
        )
        connection.commit()
    except Exception as error:
        connection.rollback()
        print("Activity log error:", error)
    finally:
        connection.close()


def admin_required():
    """Returns True when the current session belongs to the admin."""
    return session.get("admin_logged_in") is True


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template(
        "home.html"
    )


# =========================================================
# SIGNUP
# =========================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        mobile = request.form.get(
            "mobile",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ---------------------------------------------
        # BASIC VALIDATION
        # ---------------------------------------------

        if not full_name:
            flash(
                "Please enter your full name.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        if not email:
            flash(
                "Please enter your email.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        if not password:
            flash(
                "Please enter a password.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        if len(password) < 6:

            flash(
                "Password must be at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        connection = get_connection()

        try:

            existing_user = connection.execute(
                """
                SELECT id, is_verified
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()


            # -----------------------------------------
            # EMAIL ALREADY EXISTS
            # -----------------------------------------

            if existing_user:

                if existing_user["is_verified"]:

                    flash(
                        "An account with this email already exists. Please login.",
                        "error"
                    )

                    return redirect(
                        url_for("login")
                    )


                else:

                    user_id = existing_user["id"]

                    hashed_password = generate_password_hash(
                        password
                    )

                    connection.execute(
                        """
                        UPDATE users
                        SET
                            full_name = ?,
                            mobile = ?,
                            password = ?
                        WHERE id = ?
                        """,
                        (
                            full_name,
                            mobile,
                            hashed_password,
                            user_id
                        )
                    )

                    connection.commit()


            # -----------------------------------------
            # CREATE NEW USER
            # -----------------------------------------

            else:

                hashed_password = generate_password_hash(
                    password
                )

                cursor = connection.execute(
                    """
                    INSERT INTO users
                    (
                        full_name,
                        mobile,
                        email,
                        password,
                        is_verified,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (
                        full_name,
                        mobile,
                        email,
                        hashed_password,
                        datetime.now().isoformat()
                    )
                )

                connection.commit()

                user_id = cursor.lastrowid


        except Exception as error:

            connection.rollback()

            print("Signup error:", error)

            flash(
                "Something went wrong while creating your account.",
                "error"
            )

            return redirect(
                url_for("signup")
            )

        finally:

            connection.close()


        # ---------------------------------------------
        # SEND OTP
        # ---------------------------------------------

        email_sent = create_and_send_otp(
            user_id,
            email,
            "signup"
        )

        session["pending_user_id"] = user_id
        session["otp_purpose"] = "signup"

        if email_sent:
            flash(
                "OTP has been sent to your email. It is valid for 10 minutes.",
                "success"
            )
        else:
            flash(
                "OTP could not be sent to your email. Please check the server logs and Apps Script deployment.",
                "error"
            )

        return redirect(
            url_for("otp")
        )


    return render_template(
        "signup.html"
    )


# =========================================================
# OTP VERIFICATION
# =========================================================

@app.route(
    "/otp",
    methods=["GET", "POST"]
)
def otp():

    user_id = session.get(
        "pending_user_id"
    )


    if not user_id:

        flash(
            "Please signup or login first.",
            "error"
        )

        return redirect(
            url_for("signup")
        )


    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()


        connection = get_connection()

        try:

            otp_record = connection.execute(
                """
                SELECT *
                FROM otp_verifications
                WHERE
                    user_id = ?
                    AND otp_code = ?
                    AND is_used = 0
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    user_id,
                    entered_otp
                )
            ).fetchone()


            if not otp_record:

                flash(
                    "Invalid OTP. Please try again.",
                    "error"
                )

                return redirect(
                    url_for("otp")
                )


            # -----------------------------------------
            # CHECK EXPIRY
            # -----------------------------------------

            expires_at = datetime.fromisoformat(
                otp_record["expires_at"]
            )


            if datetime.now() > expires_at:

                flash(
                    "OTP has expired. Please request a new OTP.",
                    "error"
                )

                return redirect(
                    url_for("otp")
                )


            # -----------------------------------------
            # MARK OTP USED
            # -----------------------------------------

            connection.execute(
                """
                UPDATE otp_verifications
                SET is_used = 1
                WHERE id = ?
                """,
                (otp_record["id"],)
            )


            connection.execute(
                """
                UPDATE users
                SET is_verified = 1
                WHERE id = ?
                """,
                (user_id,)
            )


            connection.commit()


        except Exception as error:

            connection.rollback()

            print("OTP error:", error)

            flash(
                "Something went wrong while verifying OTP.",
                "error"
            )

            return redirect(
                url_for("otp")
            )

        finally:

            connection.close()


        # ---------------------------------------------
        # LOGIN USER
        # ---------------------------------------------

        session.pop(
            "pending_user_id",
            None
        )
        session.pop("otp_purpose", None)

        session["user_id"] = user_id


        flash(
            "Account verified successfully!",
            "success"
        )


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "otp.html"
    )


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    """Resend OTP for signup/login verification or password reset."""
    reset_user_id = session.get("reset_user_id")
    pending_user_id = session.get("pending_user_id")

    if reset_user_id:
        user_id = reset_user_id
        purpose = "reset_password"
        destination = "reset_password"
    elif pending_user_id:
        user_id = pending_user_id
        purpose = session.get("otp_purpose", "signup")
        destination = "otp"
    else:
        flash("Please start signup, login verification, or password reset first.", "error")
        return redirect(url_for("forgot_password"))

    connection = get_connection()
    try:
        user = connection.execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        connection.close()

    if not user:
        flash("Account not found. Please try again.", "error")
        return redirect(url_for("signup"))

    # Invalidate any previous unused OTP for this same purpose.
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE otp_verifications SET is_used = 1 WHERE user_id = ? AND purpose = ? AND is_used = 0",
            (user_id, purpose)
        )
        connection.commit()
    finally:
        connection.close()

    if create_and_send_otp(user_id, user["email"], purpose):
        flash("A new OTP has been sent. It is valid for 10 minutes.", "success")
    else:
        flash("OTP email could not be sent. Check the Apps Script deployment and server logs.", "error")
    return redirect(url_for(destination))


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        connection = get_connection()

        try:

            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

        finally:

            connection.close()


        if not user:

            flash(
                "No account found with this email.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        if not check_password_hash(
            user["password"],
            password
        ):

            flash(
                "Incorrect password.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        # ---------------------------------------------
        # CHECK VERIFICATION
        # ---------------------------------------------

        if not user["is_verified"]:

            session["pending_user_id"] = user["id"]
            session["otp_purpose"] = "login"


            create_and_send_otp(
                user["id"],
                user["email"],
                "login"
            )


            flash(
                "Your account is not verified. A new OTP has been sent.",
                "error"
            )


            return redirect(
                url_for("otp")
            )


        # ---------------------------------------------
        # LOGIN SUCCESS
        # ---------------------------------------------

        session.clear()

        session["user_id"] = user["id"]

        log_activity(user["id"], "User Login", "User logged in successfully.")


        flash(
            f"Welcome back, {user['full_name']}!",
            "success"
        )


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "login.html"
    )


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        connection = get_connection()

        try:

            user = connection.execute(
                """
                SELECT id, email
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

        finally:

            connection.close()


        if not user:

            flash(
                "No account found with this email.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )


        create_and_send_otp(
            user["id"],
            user["email"],
            "reset_password"
        )


        session["reset_user_id"] = user["id"]


        flash(
            "Password reset OTP has been sent to your email.",
            "success"
        )


        return redirect(
            url_for("reset_password")
        )


    return render_template(
        "forgot_password.html"
    )


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    user_id = session.get(
        "reset_user_id"
    )


    if not user_id:

        flash(
            "Please request a password reset first.",
            "error"
        )

        return redirect(
            url_for("forgot_password")
        )


    if request.method == "POST":

        otp_code = request.form.get(
            "otp",
            ""
        ).strip()

        new_password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )


        if len(new_password) < 6:

            flash(
                "Password must be at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )


        connection = get_connection()

        try:

            otp_record = connection.execute(
                """
                SELECT *
                FROM otp_verifications
                WHERE
                    user_id = ?
                    AND otp_code = ?
                    AND purpose = 'reset_password'
                    AND is_used = 0
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    user_id,
                    otp_code
                )
            ).fetchone()


            if not otp_record:

                flash(
                    "Invalid OTP.",
                    "error"
                )

                return redirect(
                    url_for("reset_password")
                )


            expires_at = datetime.fromisoformat(
                otp_record["expires_at"]
            )


            if datetime.now() > expires_at:

                flash(
                    "OTP has expired.",
                    "error"
                )

                return redirect(
                    url_for("reset_password")
                )


            hashed_password = generate_password_hash(
                new_password
            )


            connection.execute(
                """
                UPDATE users
                SET password = ?
                WHERE id = ?
                """,
                (
                    hashed_password,
                    user_id
                )
            )


            connection.execute(
                """
                UPDATE otp_verifications
                SET is_used = 1
                WHERE id = ?
                """,
                (otp_record["id"],)
            )


            connection.commit()


        except Exception as error:

            connection.rollback()

            print("Reset password error:", error)

            flash(
                "Something went wrong.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )

        finally:

            connection.close()


        session.pop(
            "reset_user_id",
            None
        )


        flash(
            "Password reset successfully. Please login.",
            "success"
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "reset_password.html"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    connection = get_connection()

    try:

        # ---------------------------------------------
        # TOTAL EXPENSE
        # ---------------------------------------------

        total_result = connection.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()


        total_expense = total_result["total"]


        # ---------------------------------------------
        # THIS MONTH EXPENSE
        # ---------------------------------------------

        current_month = datetime.now().strftime(
            "%Y-%m"
        )


        month_result = connection.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE
                user_id = ?
                AND substr(expense_date, 1, 7) = ?
            """,
            (
                user["id"],
                current_month
            )
        ).fetchone()


        monthly_expense = month_result["total"]


        # ---------------------------------------------
        # EXPENSE COUNT
        # ---------------------------------------------

        count_result = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM expenses
            WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()


        expense_count = count_result["total"]


        # ---------------------------------------------
        # RECENT EXPENSES
        # ---------------------------------------------

        recent_expenses = connection.execute(
            """
            SELECT *
            FROM expenses
            WHERE user_id = ?
            ORDER BY expense_date DESC, id DESC
            LIMIT 5
            """,
            (user["id"],)
        ).fetchall()


        # ---------------------------------------------
        # CATEGORY TOTALS
        # ---------------------------------------------

        category_totals = connection.execute(
            """
            SELECT
                category,
                COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            GROUP BY category
            ORDER BY total DESC
            """,
            (user["id"],)
        ).fetchall()


    finally:

        connection.close()


    return render_template(
        "dashboard.html",
        user=user,
        total_expense=total_expense,
        monthly_expense=monthly_expense,
        expense_count=expense_count,
        recent_expenses=recent_expenses,
        category_totals=category_totals
    )


# =========================================================
# ADD EXPENSE
# =========================================================

@app.route(
    "/add-expense",
    methods=["GET", "POST"]
)
def add_expense():

    user = get_current_user()


    if not user:

        flash(
            "Please login to add an expense.",
            "error"
        )

        return redirect(
            url_for("login")
        )


    # =====================================================
    # SAVE EXPENSE
    # =====================================================

    if request.method == "POST":

        amount = request.form.get(
            "amount",
            ""
        ).strip()

        category = request.form.get(
            "category",
            "Other"
        ).strip()

        expense_date = request.form.get(
            "expense_date",
            ""
        ).strip()

        expense_time = request.form.get(
            "expense_time",
            ""
        ).strip()

        merchant = request.form.get(
            "merchant",
            ""
        ).strip()

        payment_method = request.form.get(
            "payment_method",
            ""
        ).strip()

        note = request.form.get(
            "note",
            ""
        ).strip()


        # ---------------------------------------------
        # VALIDATION
        # ---------------------------------------------

        if not amount:

            flash(
                "Please enter the expense amount.",
                "error"
            )

            return redirect(
                url_for("add_expense")
            )


        try:

            amount_value = float(amount)

        except ValueError:

            flash(
                "Please enter a valid amount.",
                "error"
            )

            return redirect(
                url_for("add_expense")
            )


        if amount_value <= 0:

            flash(
                "Expense amount must be greater than zero.",
                "error"
            )

            return redirect(
                url_for("add_expense")
            )


        if not expense_date:

            expense_date = datetime.now().strftime(
                "%Y-%m-%d"
            )


        if not expense_time:

            expense_time = datetime.now().strftime(
                "%H:%M"
            )


        if not category:

            category = "Other"


        # ---------------------------------------------
        # SAVE TO DATABASE
        # ---------------------------------------------

        connection = get_connection()

        try:

            connection.execute(
                """
                INSERT INTO expenses
                (
                    user_id,
                    amount,
                    category,
                    expense_date,
                    expense_time,
                    merchant,
                    payment_method,
                    note,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    amount_value,
                    category,
                    expense_date,
                    expense_time,
                    merchant,
                    payment_method,
                    note,
                    datetime.now().isoformat()
                )
            )


            connection.commit()


        except Exception as error:

            connection.rollback()

            print(
                "Add expense database error:",
                error
            )


            flash(
                "Expense could not be saved. Please try again.",
                "error"
            )


            return redirect(
                url_for("add_expense")
            )


        finally:

            connection.close()


        # ---------------------------------------------
        # SUCCESS
        # ---------------------------------------------

        log_activity(
            user["id"],
            "Expense Added",
            f"Expense of ₹{amount_value:.2f} added in {category}."
        )

        flash(
            "Expense added successfully! 💜",
            "success"
        )


        return redirect(
            url_for("add_expense")
        )


    # =====================================================
    # GET PAGE
    # =====================================================

    return render_template(
        "add_expense.html",
        user=user
    )


# =========================================================
# EXPENSE HISTORY
# =========================================================

@app.route("/expense-history")
def expense_history():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    connection = get_connection()

    try:

        expenses = connection.execute(
            """
            SELECT *
            FROM expenses
            WHERE user_id = ?
            ORDER BY expense_date DESC, id DESC
            """,
            (user["id"],)
        ).fetchall()

    finally:

        connection.close()


    return render_template(
        "expense_history.html",
        user=user,
        expenses=expenses
    )


# =========================================================
# ANALYSIS
# =========================================================

@app.route("/analysis")
def analysis():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    connection = get_connection()

    try:

        category_data = connection.execute(
            """
            SELECT
                category,
                COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            GROUP BY category
            ORDER BY total DESC
            """,
            (user["id"],)
        ).fetchall()


        monthly_data = connection.execute(
            """
            SELECT
                substr(expense_date, 1, 7) AS month,
                COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            GROUP BY substr(expense_date, 1, 7)
            ORDER BY month ASC
            """,
            (user["id"],)
        ).fetchall()


        total_result = connection.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()


    finally:

        connection.close()


    return render_template(
        "analysis.html",
        user=user,
        category_data=category_data,
        monthly_data=monthly_data,
        total_expense=total_result["total"]
    )


# =========================================================
# BUDGET
# =========================================================

@app.route(
    "/budget",
    methods=["GET", "POST"]
)
def budget():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    if request.method == "POST":

        month = request.form.get(
            "month",
            ""
        ).strip()

        total_budget = request.form.get(
            "total_budget",
            "0"
        ).strip()


        try:

            total_budget_value = float(
                total_budget
            )

        except ValueError:

            flash(
                "Please enter a valid budget.",
                "error"
            )

            return redirect(
                url_for("budget")
            )


        connection = get_connection()

        try:

            existing = connection.execute(
                """
                SELECT id
                FROM budgets
                WHERE
                    user_id = ?
                    AND month = ?
                """,
                (
                    user["id"],
                    month
                )
            ).fetchone()


            if existing:

                connection.execute(
                    """
                    UPDATE budgets
                    SET total_budget = ?
                    WHERE id = ?
                    """,
                    (
                        total_budget_value,
                        existing["id"]
                    )
                )

            else:

                connection.execute(
                    """
                    INSERT INTO budgets
                    (
                        user_id,
                        month,
                        total_budget,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        user["id"],
                        month,
                        total_budget_value,
                        datetime.now().isoformat()
                    )
                )


            connection.commit()


        except Exception as error:

            connection.rollback()

            print(
                "Budget error:",
                error
            )


            flash(
                "Budget could not be saved.",
                "error"
            )

            return redirect(
                url_for("budget")
            )

        finally:

            connection.close()


        flash(
            "Budget saved successfully! 🎯",
            "success"
        )


        return redirect(
            url_for("budget")
        )


    connection = get_connection()

    try:

        budgets = connection.execute(
            """
            SELECT *
            FROM budgets
            WHERE user_id = ?
            ORDER BY month DESC
            """,
            (user["id"],)
        ).fetchall()

    finally:

        connection.close()


    return render_template(
        "budget.html",
        user=user,
        budgets=budgets
    )


# =========================================================
# REPORTS
# =========================================================

@app.route("/reports")
def reports():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    connection = get_connection()

    try:

        total_result = connection.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()


        category_data = connection.execute(
            """
            SELECT
                category,
                COUNT(*) AS count,
                COALESCE(SUM(amount), 0) AS total
            FROM expenses
            WHERE user_id = ?
            GROUP BY category
            ORDER BY total DESC
            """,
            (user["id"],)
        ).fetchall()


    finally:

        connection.close()


    return render_template(
        "reports.html",
        user=user,
        total_expense=total_result["total"],
        category_data=category_data
    )


# =========================================================
# PROFILE
# =========================================================

@app.route(
    "/profile",
    methods=["GET", "POST"]
)
def profile():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    if request.method == "POST":

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        mobile = request.form.get(
            "mobile",
            ""
        ).strip()


        connection = get_connection()

        try:

            connection.execute(
                """
                UPDATE users
                SET
                    full_name = ?,
                    mobile = ?
                WHERE id = ?
                """,
                (
                    full_name,
                    mobile,
                    user["id"]
                )
            )


            connection.commit()


        except Exception as error:

            connection.rollback()

            print(
                "Profile update error:",
                error
            )


            flash(
                "Profile could not be updated.",
                "error"
            )


        else:

            flash(
                "Profile updated successfully! 👤",
                "success"
            )


        finally:

            connection.close()


        return redirect(
            url_for("profile")
        )


    return render_template(
        "profile.html",
        user=user
    )


# =========================================================
# SETTINGS
# =========================================================

@app.route("/settings")
def settings():

    user = get_current_user()


    if not user:

        return redirect(
            url_for("login")
        )


    return render_template(
        "settings.html",
        user=user
    )


# =========================================================
# ABOUT
# =========================================================

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


# =========================================================
# CONTACT
# =========================================================

@app.route(
    "/contact",
    methods=["GET", "POST"]
)
def contact():

    if request.method == "POST":

        flash(
            "Thank you for contacting us! We will get back to you soon.",
            "success"
        )

        return redirect(
            url_for("contact")
        )


    return render_template(
        "contact.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    user_id = session.get("user_id")

    if user_id:
        log_activity(user_id, "User Logout", "User logged out.")

    session.clear()


    flash(
        "You have been logged out successfully.",
        "success"
    )


    return redirect(
        url_for("login")
    )


# =========================================================
# ADMIN LOGIN
# =========================================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not ADMIN_EMAIL or not ADMIN_PASSWORD:
            flash(
                "Admin login is not configured. Please check your Environment variables.",
                "error"
            )
            return redirect(url_for("admin_login"))

        if not (
            hmac.compare_digest(email, ADMIN_EMAIL)
            and hmac.compare_digest(password, ADMIN_PASSWORD)
        ):
            flash("Invalid admin email or password.", "error")
            return redirect(url_for("admin_login"))

        session.clear()
        session["admin_logged_in"] = True
        session["admin_email"] = ADMIN_EMAIL

        flash("Admin login successful!", "success")

        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin/dashboard")
def admin_dashboard():

    if not admin_required():
        return redirect(url_for("admin_login"))

    connection = get_connection()

    try:
        total_users = connection.execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"]

        verified_users = connection.execute(
            "SELECT COUNT(*) AS total FROM users WHERE is_verified = 1"
        ).fetchone()["total"]

        total_expense = connection.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM expenses"
        ).fetchone()["total"]

        expense_count = connection.execute(
            "SELECT COUNT(*) AS total FROM expenses"
        ).fetchone()["total"]

        recent_users = connection.execute(
            """
            SELECT id, full_name, email, is_verified, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 8
            """
        ).fetchall()

        recent_activity = connection.execute(
            """
            SELECT action, details, created_at
            FROM activity_logs
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

    finally:
        connection.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        verified_users=verified_users,
        total_expense=total_expense,
        expense_count=expense_count,
        recent_users=recent_users,
        recent_activity=recent_activity,
        user_activity=user_activity
    )


# =========================================================
# ADMIN USERS
# =========================================================

@app.route("/admin/users")
def admin_users():

    if not admin_required():
        return redirect(url_for("admin_login"))

    connection = get_connection()

    try:
        users = connection.execute(
            """
            SELECT id, full_name, mobile, email, is_verified, role, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("admin_users.html", users=users)


# =========================================================
# ADMIN EXPENSES
# =========================================================

@app.route("/admin/expenses")
def admin_expenses():

    if not admin_required():
        return redirect(url_for("admin_login"))

    connection = get_connection()

    try:
        expenses = connection.execute(
            """
            SELECT
                expenses.*,
                users.full_name,
                users.email
            FROM expenses
            LEFT JOIN users ON users.id = expenses.user_id
            ORDER BY expenses.expense_date DESC, expenses.id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("admin_expenses.html", expenses=expenses)


# =========================================================
# ADMIN ACTIVITY
# =========================================================

@app.route("/admin/activity")
def admin_activity():

    if not admin_required():
        return redirect(url_for("admin_login"))

    connection = get_connection()

    try:
        activities = connection.execute(
            """
            SELECT
                activity_logs.*,
                users.full_name,
                users.email
            FROM activity_logs
            LEFT JOIN users ON users.id = activity_logs.user_id
            ORDER BY activity_logs.id DESC
            LIMIT 200
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("admin_activity.html", activities=activities)


# =========================================================
# ADMIN REPORTS
# =========================================================

@app.route("/admin/reports")
def admin_reports():

    if not admin_required():
        return redirect(url_for("admin_login"))

    connection = get_connection()

    try:
        total_result = connection.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM expenses"
        ).fetchone()

        category_data = connection.execute(
            """
            SELECT category, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS total
            FROM expenses
            GROUP BY category
            ORDER BY total DESC
            """
        ).fetchall()

        monthly_data = connection.execute(
            """
            SELECT substr(expense_date, 1, 7) AS month,
                   COALESCE(SUM(amount), 0) AS total
            FROM expenses
            GROUP BY substr(expense_date, 1, 7)
            ORDER BY month ASC
            """
        ).fetchall()

    finally:
        connection.close()

    return render_template(
        "admin_reports.html",
        total_expense=total_result["total"],
        category_data=category_data,
        monthly_data=monthly_data
    )


# =========================================================
# ADMIN LOGOUT
# =========================================================

@app.route("/admin/logout")
def admin_logout():

    session.pop("admin_logged_in", None)
    session.pop("admin_email", None)

    flash("Admin logged out successfully.", "success")
    return redirect(url_for("admin_login"))


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The page you are looking for does not exist.</p>
    """, 404


@app.errorhandler(500)
def internal_server_error(error):

    return """
    <h1>500 - Internal Server Error</h1>
    <p>Something went wrong on the server.</p>
    """, 500


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    create_tables()

    app.run(
        debug=True
    )
