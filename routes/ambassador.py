from flask import Blueprint, jsonify, render_template, request, redirect, flash
from markupsafe import escape
from app import get_db, require_role, current_intern, current_staff, clean_text, record_referral_click, log_error, encrypt_upi, decrypt_upi, now_str, log_security_event, app_logger

ambassador_bp = Blueprint('ambassador', __name__)

@ambassador_bp.route("/ambassador")
def ambassador_page():
    """Intern-facing College Ambassador tab (Â§6.6)."""
    if not current_intern():
        return redirect("/#signin")
    return render_template("ambassador.html")


@ambassador_bp.route("/r/click")
def referral_click():
    """Anonymous click beacon for /?ref=<code> (Â§6.1). Always 204 â€” a bad or
    unknown code must never reveal whether it exists."""
    try:
        code = clean_text(request.args.get("ref"))
        if code:
            with get_db() as conn:
                record_referral_click(conn, code)
                conn.commit()
    except Exception as e:
        log_error("referral-click", e)
    return ("", 204)


@ambassador_bp.route("/intern/ambassador")
def intern_ambassador():
    """Funnel stats, referral link, referral-coin balance, masked UPI (Â§6.6)."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        with get_db() as conn:
            acct = conn.execute(
                "SELECT id, name, referral_code, upi_id_encrypted FROM intern_accounts WHERE id=?",
                (intern["id"],)).fetchone()
            if not acct:
                return jsonify({"status": "error", "message": "Account not found"}), 404

            code = acct["referral_code"] or ensure_referral_code(conn, acct["id"], acct["name"])
            conn.commit()

            funnel = {"clicked": 0, "signed_up": 0, "converted": 0}
            for r in conn.execute(
                    "SELECT status, COUNT(*) c FROM referrals WHERE referrer_intern_id=? GROUP BY status",
                    (acct["id"],)).fetchall():
                funnel[r["status"]] = r["c"]
            # a signup is also a click, a conversion is also a signup
            funnel["clicked"]   += funnel["signed_up"] + funnel["converted"]
            funnel["signed_up"] += funnel["converted"]

            referrals = [row_to_dict(r) for r in conn.execute(
                "SELECT r.status, r.created_at, r.flagged, a.name AS referred_name "
                "FROM referrals r LEFT JOIN intern_accounts a ON a.id = r.referred_intern_id "
                "WHERE r.referrer_intern_id=? AND r.referred_intern_id IS NOT NULL "
                "ORDER BY r.id DESC LIMIT 50", (acct["id"],)).fetchall()]

            balances = get_coin_balances(conn, acct["id"])
            pending = conn.execute(
                "SELECT COALESCE(SUM(amount),0) v FROM ambassador_withdrawals "
                "WHERE intern_id=? AND status IN ('pending','approved')", (acct["id"],)
            ).fetchone()["v"]
            withdrawals = [row_to_dict(r) for r in conn.execute(
                "SELECT id, amount, status, requested_at, admin_note FROM ambassador_withdrawals "
                "WHERE intern_id=? ORDER BY id DESC LIMIT 20", (acct["id"],)).fetchall()]

        # never send the UPI itself â€” only whether one exists, and its mask
        upi_plain = decrypt_upi(acct["upi_id_encrypted"]) if acct["upi_id_encrypted"] else None
        return jsonify({
            "status": "success",
            "enabled": AMBASSADOR_ENABLED,
            "code": code,
            "link": referral_link(code),
            "funnel": funnel,
            "referrals": referrals,
            "referral_balance": balances["referral"],
            "pending_withdrawal": pending,
            "available": max(0, balances["referral"] - pending),
            "upi_masked": mask_upi(upi_plain) if upi_plain else "",
            "has_upi": bool(acct["upi_id_encrypted"]),
            "withdrawals": withdrawals,
        })
    except Exception as e:
        log_error("intern-ambassador", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@ambassador_bp.route("/intern/ambassador/upi", methods=["POST"])
def intern_ambassador_upi():
    """Store the payout UPI id â€” encrypted at rest, never returned in clear."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ip = get_client_ip()
        allowed, retry_after = rate_check(f"upi:{intern['id']}", *RL_UPI_UPDATE)
        if not allowed:
            log_abuse(ip, "/intern/ambassador/upi", f"upi:{intern['id']}", "rate_limit")
            return jsonify({"status": "error", "message": "Too many updates. Try again later.",
                            "retry_after": retry_after}), 429

        upi = clean_text((request.get_json(silent=True) or {}).get("upi_id"))
        if not is_valid_upi(upi):
            return jsonify({"status": "error", "message": "Enter a valid UPI id, e.g. name@bank."}), 400

        cipher = encrypt_upi(upi)
        if not cipher:
            # Â§5.4 â€” refuse rather than fall back to plaintext.
            log_error("upi-encrypt", RuntimeError("FERNET_KEY missing or invalid"))
            return jsonify({"status": "error",
                            "message": "Payouts are temporarily unavailable. Please try later."}), 503

        with get_db() as conn:
            conn.execute("UPDATE intern_accounts SET upi_id_encrypted=? WHERE id=?",
                         (cipher, intern["id"]))
            conn.commit()
        return jsonify({"status": "success", "message": "UPI id saved.",
                        "upi_masked": mask_upi(upi)})
    except Exception as e:
        log_error("intern-ambassador-upi", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@ambassador_bp.route("/intern/ambassador/withdraw", methods=["POST"])
def intern_ambassador_withdraw():
    """Request a payout. Draws ONLY on the referral ledger (Â§6.5)."""
    try:
        intern = current_intern()
        if not intern:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        ip = get_client_ip()
        allowed, retry_after = rate_check(f"wd:{intern['id']}", *RL_WITHDRAWAL)
        if not allowed:
            log_abuse(ip, "/intern/ambassador/withdraw", f"wd:{intern['id']}", "rate_limit")
            return jsonify({"status": "error", "message": "Too many requests. Try again later.",
                            "retry_after": retry_after}), 429

        try:
            amount = int((request.get_json(silent=True) or {}).get("amount") or 0)
        except (TypeError, ValueError):
            amount = 0
        if amount <= 0:
            return jsonify({"status": "error", "message": "Enter an amount."}), 400

        with get_db() as conn:
            acct = conn.execute(
                "SELECT upi_id_encrypted FROM intern_accounts WHERE id=?", (intern["id"],)).fetchone()
            if not acct or not acct["upi_id_encrypted"]:
                return jsonify({"status": "error",
                                "message": "Add your UPI id before requesting a withdrawal."}), 400

            balance = get_coin_balances(conn, intern["id"])["referral"]
            pending = conn.execute(
                "SELECT COALESCE(SUM(amount),0) v FROM ambassador_withdrawals "
                "WHERE intern_id=? AND status IN ('pending','approved')", (intern["id"],)
            ).fetchone()["v"]
            available = balance - pending
            if amount > available:
                return jsonify({"status": "error",
                                "message": f"You can withdraw at most â‚¹{available}."}), 400

            conn.execute(
                "INSERT INTO ambassador_withdrawals (intern_id, amount, status) VALUES (?,?, 'pending')",
                (intern["id"], amount))
            conn.commit()
        return jsonify({"status": "success",
                        "message": "Withdrawal requested. We'll review it shortly."})
    except Exception as e:
        log_error("intern-ambassador-withdraw", e)
        return jsonify({"status": "error", "message": "Error"}), 500


@ambassador_bp.route("/admin/ambassador-payouts")
def admin_ambassador_payouts():
    """Payout queue (Â§6.5) â€” mirrors /admin/post-hire-deposits."""
    if not (is_admin_request() or current_staff()):
        return redirect("/admin/login")
    with get_db() as conn:
        rows = [row_to_dict(r) for r in conn.execute(
            "SELECT w.*, a.name AS intern_name, a.email AS intern_email "
            "FROM ambassador_withdrawals w JOIN intern_accounts a ON a.id = w.intern_id "
            "ORDER BY CASE w.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, w.id DESC"
        ).fetchall()]
    # UPI is deliberately absent here: it is never rendered in a list view (Â§5.4).
    return render_template("admin_ambassador_payouts.html", rows=rows,
                           fernet_ready=bool(FERNET_KEY))


@ambassador_bp.route("/admin/ambassador-payouts/<int:wid>/upi", methods=["POST"])
def admin_ambassador_reveal_upi(wid):
    """Decrypt and return the UPI id ONCE, logging who looked and when (Â§6.5)."""
    if not (is_admin_request() or current_staff()):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    who = (session.get("staff_email") or session.get("admin_id") or "admin")
    with get_db() as conn:
        row = conn.execute(
            "SELECT w.id, a.upi_id_encrypted FROM ambassador_withdrawals w "
            "JOIN intern_accounts a ON a.id = w.intern_id WHERE w.id=?", (wid,)).fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Not found"}), 404
        upi = decrypt_upi(row["upi_id_encrypted"])
        if not upi:
            return jsonify({"status": "error",
                            "message": "Could not decrypt â€” check FERNET_KEY."}), 503
        conn.execute("UPDATE ambassador_withdrawals SET upi_viewed_by=?, upi_viewed_at=? WHERE id=?",
                     (str(who), now_str(), wid))
        conn.commit()
    log_abuse(get_client_ip(), "/admin/ambassador-payouts", f"upi_view:{wid}", "upi_revealed")
    return jsonify({"status": "success", "upi_id": upi})


@ambassador_bp.route("/admin/ambassador-payouts/<int:wid>/decision", methods=["POST"])
def admin_ambassador_decision(wid):
    """Mark a payout Paid or Rejected. On Paid, debit the referral ledger."""
    if not (is_admin_request() or current_staff()):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    decision = clean_text(data.get("decision"))
    note = clean_text(data.get("note")) or ""
    if decision not in ("paid", "rejected"):
        return jsonify({"status": "error", "message": "decision must be paid|rejected"}), 400

    who = session.get("staff_id") or session.get("admin_id")
    with get_db() as conn:
        w = conn.execute("SELECT * FROM ambassador_withdrawals WHERE id=?", (wid,)).fetchone()
        if not w:
            return jsonify({"status": "error", "message": "Not found"}), 404
        if w["status"] in ("paid", "rejected"):
            return jsonify({"status": "error", "message": "Already reviewed."}), 409

        if decision == "paid":
            # The debit is the guard: it refuses to overdraw and refuses to run
            # twice for the same withdrawal id.
            new_bal = debit_referral_coins(
                conn, w["intern_id"], w["amount"],
                f"Ambassador payout #{wid}", withdrawal_id=wid)
            if new_bal is None:
                return jsonify({"status": "error",
                                "message": "Balance no longer covers this payout."}), 409

        conn.execute(
            "UPDATE ambassador_withdrawals SET status=?, reviewed_by_admin_id=?, reviewed_at=?, "
            "admin_note=? WHERE id=?", (decision, who, now_str(), note, wid))
        conn.commit()
    return jsonify({"status": "success", "message": f"Marked {decision}."})
