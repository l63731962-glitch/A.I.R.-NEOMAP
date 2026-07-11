from datetime import date as _date
from flask import Blueprint, request, jsonify
from app.database import db
from app.models import (
    Member, Church, CellGroup, Service, Visitor, FollowUpAssignment,
    FollowUpTeamMember, NotificationLog,
)
from app.auth import (
    login_required, role_required, church_scoped,
    generate_token, ROLE_ADMIN, ROLE_LEADER, ROLE_ADULT,
)
from app.attendance_logic import (
    submit_attendance, complete_follow_up, get_pending_queue_for_user,
    get_admin_overview, get_unassigned_members, get_leader_accountability_overview,
    get_upcoming_birthdays, submit_rsvp, get_rsvp_no_shows, get_engagement_summary,
)

bp = Blueprint("neomap", __name__, url_prefix="/api")


def _parse_date(value):
    """SQLAlchemy's Date column needs an actual date object, not the
    'YYYY-MM-DD' string an HTML <input type="date"> or JSON body sends.
    Returns None for empty/missing input, and 400s via ValueError on
    anything malformed rather than letting a raw DB error leak out."""
    if not value:
        return None
    if isinstance(value, _date):
        return value
    return _date.fromisoformat(value)


# ---------- AUTH ----------

@bp.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")

    member = Member.query.filter_by(email=email).first()
    if not member or not member.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    if member.role == "child":
        # children never authenticate directly, no exceptions
        return jsonify({"error": "This account cannot log in directly"}), 403

    token = generate_token(member.id, member.church_id, member.role)
    return jsonify({"token": token, "member": member.to_dict(include_sensitive=True)})


@bp.route("/auth/bootstrap", methods=["POST"])
def bootstrap_admin():
    """
    One-time setup: creates the very first admin account for a
    church. Only works when that church has zero members — the
    moment one exists, this route 403s forever. This solves the
    chicken-and-egg problem where register_member() requires an
    admin token, but no admin token can exist until someone is
    registered.
    """
    data = request.json or {}
    church_name = data.get("church_name")
    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")

    missing = [f for f in ["church_name", "full_name", "email", "password"] if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    existing_email = Member.query.filter_by(email=email).first()
    if existing_email:
        return jsonify({"error": "That email is already registered — sign in instead"}), 409

    church = Church.query.filter_by(name=church_name).first()
    if church:
        already_has_members = Member.query.filter_by(church_id=church.id).first()
        if already_has_members:
            return jsonify({"error": "This church already has an admin — ask them for access, sign in, or use a different church name"}), 403
    else:
        church = Church(name=church_name)
        db.session.add(church)
        db.session.commit()

    admin = Member(
        church_id=church.id,
        full_name=full_name,
        role=ROLE_ADMIN,
        email=email,
    )
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()

    church.admin_user_id = admin.id
    db.session.commit()

    token = generate_token(admin.id, admin.church_id, admin.role)
    return jsonify({"token": token, "member": admin.to_dict(include_sensitive=True)}), 201


@bp.route("/auth/me", methods=["GET"])
@login_required
def me():
    """
    Restores identity from a stored token on page reload — without
    this, a valid token with no cached member data (e.g. after a
    browser refresh) has no way to become a full session again.
    """
    member = Member.query.get_or_404(request.current_member["member_id"])
    return jsonify(member.to_dict(include_sensitive=True))


# ---------- MEMBER REGISTRATION (leader/admin only, server-enforced) ----------

@bp.route("/members/register", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
@church_scoped
def register_member():
    data = request.json or {}
    church_id = request.current_member["church_id"]

    required = ["full_name", "role"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    if data["role"] == "child" and not data.get("guardian_id"):
        return jsonify({"error": "Children must have a guardian_id — no independent accounts"}), 400

    email = data.get("email")
    if email:
        existing_email = Member.query.filter_by(email=email).first()
        if existing_email:
            return jsonify({"error": "That email is already registered to another member"}), 409

    try:
        dob = _parse_date(data.get("date_of_birth"))
    except ValueError:
        return jsonify({"error": "date_of_birth must be in YYYY-MM-DD format"}), 400

    member = Member(
        church_id=church_id,
        full_name=data["full_name"],
        role=data["role"],
        date_of_birth=dob,
        guardian_id=data.get("guardian_id"),
        phone=data.get("phone"),
        area=data.get("area"),
        email=email,
        cell_id=data.get("cell_id"),
        created_by=request.current_member["member_id"],
    )

    if data.get("password") and data["role"] != "child":
        member.set_password(data["password"])

    db.session.add(member)
    db.session.commit()
    return jsonify(member.to_dict(include_sensitive=True)), 201


@bp.route("/members", methods=["GET"])
@login_required
@church_scoped
def list_members():
    church_id = request.current_member["church_id"]
    members = Member.query.filter_by(church_id=church_id, membership_status="active").all()
    return jsonify([m.to_dict() for m in members])


# ---------- CELLS ----------

@bp.route("/cells", methods=["GET"])
@login_required
@church_scoped
def list_cells():
    church_id = request.current_member["church_id"]
    cells = CellGroup.query.filter_by(church_id=church_id).all()
    return jsonify([c.to_dict() for c in cells])


@bp.route("/cells", methods=["POST"])
@role_required(ROLE_ADMIN)
@church_scoped
def create_cell():
    data = request.json or {}
    church_id = request.current_member["church_id"]

    if not data.get("name") or not data.get("leader_id"):
        return jsonify({"error": "name and leader_id are required"}), 400

    cell = CellGroup(
        church_id=church_id,
        name=data["name"],
        leader_id=data["leader_id"],
        meeting_day=data.get("meeting_day"),
    )
    db.session.add(cell)
    db.session.commit()
    return jsonify(cell.to_dict()), 201


@bp.route("/cells/unassigned", methods=["GET"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
@church_scoped
def unassigned_members():
    church_id = request.current_member["church_id"]
    members = get_unassigned_members(church_id)
    return jsonify([m.to_dict(include_sensitive=True) for m in members])


# ---------- SERVICES ----------

@bp.route("/services", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
@church_scoped
def create_service():
    data = request.json or {}
    church_id = request.current_member["church_id"]

    if not data.get("name") or not data.get("date"):
        return jsonify({"error": "name and date are required"}), 400

    try:
        service_date = _parse_date(data["date"])
    except ValueError:
        return jsonify({"error": "date must be in YYYY-MM-DD format"}), 400

    service = Service(
        church_id=church_id,
        name=data["name"],
        date=service_date,
        type=data.get("type", "sunday"),
    )
    db.session.add(service)
    db.session.commit()
    return jsonify(service.to_dict()), 201


# ---------- ATTENDANCE — the core loop ----------

@bp.route("/attendance/submit", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
@church_scoped
def submit_attendance_route():
    data = request.json or {}
    church_id = request.current_member["church_id"]
    service_id = data.get("service_id")
    present_member_ids = data.get("present_member_ids", [])
    new_visitors = data.get("new_visitors", [])  # [{full_name, phone}, ...]

    if not service_id:
        return jsonify({"error": "service_id is required"}), 400

    # quick-add visitors before the diff runs — they aren't part of
    # the roster yet, so they never appear on an absence list
    for v in new_visitors:
        if v.get("full_name"):
            db.session.add(Visitor(
                church_id=church_id,
                full_name=v["full_name"],
                phone=v.get("phone"),
                invited_by=request.current_member["member_id"],
            ))
    db.session.commit()

    records = submit_attendance(
        church_id=church_id,
        service_id=service_id,
        present_member_ids=present_member_ids,
        submitted_by_id=request.current_member["member_id"],
    )

    return jsonify({
        "absent_count": len(records),
        "records": [r.to_dict() for r in records],
    }), 201


# ---------- FOLLOW-UP QUEUE ----------

@bp.route("/follow-up/queue", methods=["GET"])
@login_required
def my_follow_up_queue():
    """
    Returns ONLY the current user's own pending assignments —
    scoped server-side by their member_id from the token, never
    by a client-supplied filter. A leader cannot pull another
    leader's queue by changing a query param.
    """
    user_id = request.current_member["member_id"]
    assignments = get_pending_queue_for_user(user_id)
    return jsonify([a.to_dict() for a in assignments])


@bp.route("/follow-up/<int:assignment_id>/complete", methods=["POST"])
@login_required
def complete_follow_up_route(assignment_id):
    data = request.json or {}
    outcome = data.get("outcome_status")
    note = data.get("note", "")

    assignment = FollowUpAssignment.query.get_or_404(assignment_id)

    # a user can only complete their OWN assignment, admin excepted
    caller_id = request.current_member["member_id"]
    caller_role = request.current_member["role"]
    if assignment.assigned_to != caller_id and caller_role != ROLE_ADMIN:
        return jsonify({"error": "Forbidden — not your assignment"}), 403

    try:
        record = complete_follow_up(
            assignment_id=assignment_id,
            outcome_status=outcome,
            note=note,
            completed_by_id=caller_id,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(record.to_dict())


# ---------- ADMIN DASHBOARD ----------

@bp.route("/admin/follow-up/overview", methods=["GET"])
@role_required(ROLE_ADMIN)
@church_scoped
def admin_overview():
    church_id = request.current_member["church_id"]
    return jsonify(get_admin_overview(church_id))


@bp.route("/admin/leaders/overview", methods=["GET"])
@role_required(ROLE_ADMIN)
@church_scoped
def leader_accountability_overview():
    """
    Separate section, distinct from member follow-up: which leaders
    are showing up consistently and which aren't. Flags at 2
    consecutive absences (earlier than the member threshold) since
    a leader's own inconsistency undermines the whole follow-up chain.
    """
    church_id = request.current_member["church_id"]
    return jsonify(get_leader_accountability_overview(church_id))


# ---------- FEATURE 1: BIRTHDAYS ----------

@bp.route("/members/birthdays", methods=["GET"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
@church_scoped
def upcoming_birthdays():
    """Warm, non-corrective contact list -- not tied to absence."""
    church_id = request.current_member["church_id"]
    days_ahead = request.args.get("days_ahead", default=7, type=int)
    return jsonify(get_upcoming_birthdays(church_id, days_ahead))


# ---------- FEATURE 4: EVENT RSVP ----------

@bp.route("/services/<int:service_id>/rsvp", methods=["POST"])
@login_required
def rsvp_route(service_id):
    data = request.json or {}
    response = data.get("response", "yes")
    if response not in ("yes", "no", "maybe"):
        return jsonify({"error": "response must be yes, no, or maybe"}), 400

    rsvp = submit_rsvp(
        service_id=service_id,
        member_id=request.current_member["member_id"],
        response=response,
    )
    return jsonify(rsvp.to_dict()), 201


@bp.route("/services/<int:service_id>/rsvp-no-shows", methods=["GET"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
def rsvp_no_shows(service_id):
    """Members who RSVP'd yes but weren't marked present -- stronger drift signal than a plain absence."""
    return jsonify(get_rsvp_no_shows(service_id))


# ---------- FEATURE 5: ENGAGEMENT SUMMARY ----------

@bp.route("/members/<int:member_id>/engagement", methods=["GET"])
@role_required(ROLE_ADMIN, ROLE_LEADER)
@church_scoped
def member_engagement(member_id):
    """Multi-service attendance rate, not just Sunday -- prevents false escalation on differently-engaged members."""
    lookback = request.args.get("lookback", default=8, type=int)
    return jsonify(get_engagement_summary(member_id, lookback))


@bp.route("/admin/follow-up/all", methods=["GET"])
@role_required(ROLE_ADMIN)
@church_scoped
def admin_all_pending():
    """Every open assignment church-wide, including stale/stacked ones, for the admin to see who's falling behind."""
    church_id = request.current_member["church_id"]
    assignments = (
        FollowUpAssignment.query
        .join(Member, FollowUpAssignment.assigned_to == Member.id)
        .filter(Member.church_id == church_id, FollowUpAssignment.status == "pending")
        .order_by(FollowUpAssignment.created_at.asc())
        .all()
    )
    return jsonify([a.to_dict() for a in assignments])


# ---------- GENERAL FOLLOW-UP TEAM ----------

@bp.route("/admin/follow-up-team", methods=["GET"])
@role_required(ROLE_ADMIN)
@church_scoped
def list_follow_up_team():
    church_id = request.current_member["church_id"]
    team = FollowUpTeamMember.query.filter_by(church_id=church_id).all()
    return jsonify([t.to_dict() for t in team])


@bp.route("/admin/follow-up-team", methods=["POST"])
@role_required(ROLE_ADMIN)
@church_scoped
def add_follow_up_team_member():
    """
    Adds a member to the church's general follow-up team. Unassigned
    absences round-robin across everyone active on this list, instead
    of all landing on a single admin.
    """
    data = request.json or {}
    church_id = request.current_member["church_id"]
    member_id = data.get("member_id")
    if not member_id:
        return jsonify({"error": "member_id is required"}), 400

    target = Member.query.get_or_404(member_id)
    if target.church_id != church_id:
        return jsonify({"error": "member does not belong to this church"}), 403

    existing = FollowUpTeamMember.query.filter_by(church_id=church_id, member_id=member_id).first()
    if existing:
        existing.active = True
        db.session.commit()
        return jsonify(existing.to_dict())

    team_member = FollowUpTeamMember(church_id=church_id, member_id=member_id, active=True)
    db.session.add(team_member)
    db.session.commit()
    return jsonify(team_member.to_dict()), 201


@bp.route("/admin/follow-up-team/<int:team_member_id>", methods=["DELETE"])
@role_required(ROLE_ADMIN)
@church_scoped
def remove_follow_up_team_member(team_member_id):
    """Soft-remove: sets inactive rather than deleting, so past
    assignment history tied to this row stays intact."""
    team_member = FollowUpTeamMember.query.get_or_404(team_member_id)
    team_member.active = False
    db.session.commit()
    return jsonify(team_member.to_dict())


# ---------- CHURCH ESCALATION CONFIG ----------

@bp.route("/admin/church/escalation-settings", methods=["GET"])
@role_required(ROLE_ADMIN)
@church_scoped
def get_escalation_settings():
    church_id = request.current_member["church_id"]
    church = Church.query.get_or_404(church_id)
    return jsonify({
        "follow_up_threshold": church.follow_up_threshold,
        "leader_escalation_days": church.leader_escalation_days,
        "senior_leadership_id": church.senior_leadership_id,
        "senior_leadership_name": church.members and next(
            (m.full_name for m in church.members if m.id == church.senior_leadership_id), None
        ),
    })


@bp.route("/admin/church/escalation-settings", methods=["POST"])
@role_required(ROLE_ADMIN)
@church_scoped
def update_escalation_settings():
    """
    Configures the optional senior-leadership tier above admin.
    Leaving senior_leadership_id unset (null) keeps a flat
    admin-is-top structure — nothing changes for churches that
    don't need this tier.
    """
    data = request.json or {}
    church_id = request.current_member["church_id"]
    church = Church.query.get_or_404(church_id)

    if "follow_up_threshold" in data:
        church.follow_up_threshold = data["follow_up_threshold"]
    if "leader_escalation_days" in data:
        church.leader_escalation_days = data["leader_escalation_days"]
    if "senior_leadership_id" in data:
        senior_id = data["senior_leadership_id"]
        if senior_id is not None:
            senior = Member.query.get_or_404(senior_id)
            if senior.church_id != church_id:
                return jsonify({"error": "senior_leadership_id must belong to this church"}), 403
        church.senior_leadership_id = senior_id

    db.session.commit()
    return jsonify({
        "follow_up_threshold": church.follow_up_threshold,
        "leader_escalation_days": church.leader_escalation_days,
        "senior_leadership_id": church.senior_leadership_id,
    })


# ---------- NOTIFICATION LOG ----------

@bp.route("/my/notifications", methods=["GET"])
@login_required
def my_notifications():
    """
    A user's own notification history — currently all entries are
    status='logged_only' since no SMS/email provider is wired in
    yet. This endpoint exists now so the frontend can already build
    against it; the only future change is NotificationLog.status
    moving from 'logged_only' to 'sent'/'failed' once a provider
    is connected in _log_notification().
    """
    user_id = request.current_member["member_id"]
    logs = (
        NotificationLog.query
        .filter_by(recipient_member_id=user_id)
        .order_by(NotificationLog.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify([n.to_dict() for n in logs])