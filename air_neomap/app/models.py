from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import db


class Church(db.Model):
    __tablename__ = "churches"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    denomination = db.Column(db.String(100))
    address = db.Column(db.String(300))
    admin_user_id = db.Column(db.Integer, db.ForeignKey("members.id", use_alter=True))
    senior_leadership_id = db.Column(db.Integer, db.ForeignKey("members.id", use_alter=True), nullable=True)
    # Optional tier above admin -- senior pastor, board chair, etc.
    # Leader-accountability escalations that admin hasn't resolved
    # route here. Nullable: churches with a flat admin-is-top
    # structure simply never populate this and nothing changes.
    follow_up_threshold = db.Column(db.Integer, default=3)
    leader_escalation_days = db.Column(db.Integer, default=14)
    # If a leader-accountability flag sits unresolved this many days,
    # it escalates to senior_leadership_id (if set).
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship(
        "Member", backref="church", lazy=True, foreign_keys="Member.church_id"
    )
    cells = db.relationship("CellGroup", backref="church", lazy=True)
    services = db.relationship("Service", backref="church", lazy=True)
    visitors = db.relationship("Visitor", backref="church", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "denomination": self.denomination,
            "follow_up_threshold": self.follow_up_threshold,
            "leader_escalation_days": self.leader_escalation_days,
        }


class FollowUpTeamMember(db.Model):
    """
    Real team concept, replacing the old single-admin fallback.
    Unassigned members' absences round-robin across everyone in
    this table for a church, rather than dumping every unassigned
    absence on one person.
    """
    __tablename__ = "follow_up_team_members"

    id = db.Column(db.Integer, primary_key=True)
    church_id = db.Column(db.Integer, db.ForeignKey("churches.id"), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    member = db.relationship("Member", foreign_keys=[member_id])

    def to_dict(self):
        return {
            "id": self.id,
            "member_id": self.member_id,
            "member_name": self.member.full_name if self.member else None,
            "active": self.active,
        }


class NotificationLog(db.Model):
    """
    Push-notification audit trail. The actual SMS/email send is
    provider-agnostic (Mailjet, Twilio, whatever gets picked) --
    this table just records intent and outcome so the system is
    push-ready the moment a provider is wired in, without another
    schema change.
    """
    __tablename__ = "notification_logs"

    id = db.Column(db.Integer, primary_key=True)
    recipient_member_id = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=False)
    channel = db.Column(db.String(20), default="none")  # sms | email | none (logged-only, no provider yet)
    trigger = db.Column(db.String(50))  # new_assignment | escalation | leader_accountability
    related_assignment_id = db.Column(db.Integer, db.ForeignKey("follow_up_assignments.id"), nullable=True)
    status = db.Column(db.String(20), default="pending")  # pending | sent | failed | logged_only
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "recipient_member_id": self.recipient_member_id,
            "channel": self.channel,
            "trigger": self.trigger,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


class Member(db.Model):
    __tablename__ = "members"

    id = db.Column(db.Integer, primary_key=True)
    church_id = db.Column(db.Integer, db.ForeignKey("churches.id"), nullable=False)

    full_name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="adult")  # adult | leader | admin | child
    date_of_birth = db.Column(db.Date, nullable=True)

    guardian_id = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=True)

    phone = db.Column(db.String(30))
    area = db.Column(db.String(150))  # neighborhood/zone, not full street address
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)  # null for children

    joined_date = db.Column(db.Date, default=date.today)
    membership_status = db.Column(db.String(20), default="active")  # active | inactive

    cell_id = db.Column(db.Integer, db.ForeignKey("cell_groups.id"), nullable=True)
    consecutive_absences = db.Column(db.Integer, default=0)

    tracked_for_attendance = db.Column(db.Boolean, default=True)
    # Leaders/admins are tracked for their own attendance by default.
    # Set False for roles that don't have a Sunday-attendance
    # expectation at THIS church -- e.g. a senior_leadership_id
    # contact who oversees multiple congregations, or a secondary
    # admin account used only for system configuration. Regular
    # cell leaders should almost always stay True.

    created_by = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    guardian = db.relationship("Member", remote_side=[id], foreign_keys=[guardian_id])
    attendance_records = db.relationship(
        "AttendanceRecord", backref="member", lazy=True, foreign_keys="AttendanceRecord.member_id"
    )

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw_password)

    def to_dict(self, include_sensitive=False):
        data = {
            "id": self.id,
            "full_name": self.full_name,
            "role": self.role,
            "membership_status": self.membership_status,
            "cell_id": self.cell_id,
            "cell_name": self.cell.name if self.cell_id and self.cell else None,
            "consecutive_absences": self.consecutive_absences,
            "joined_date": self.joined_date.isoformat() if self.joined_date else None,
        }
        if include_sensitive:
            data.update({
                "phone": self.phone,
                "area": self.area,
                "email": self.email,
                "guardian_id": self.guardian_id,
                "guardian_name": self.guardian.full_name if self.guardian else None,
            })
        return data


class CellGroup(db.Model):
    __tablename__ = "cell_groups"

    id = db.Column(db.Integer, primary_key=True)
    church_id = db.Column(db.Integer, db.ForeignKey("churches.id"), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey("members.id", use_alter=True), nullable=False)
    meeting_day = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship(
        "Member", backref="cell", lazy=True, foreign_keys="Member.cell_id"
    )
    leader = db.relationship("Member", foreign_keys=[leader_id])

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "leader_id": self.leader_id,
            "leader_name": self.leader.full_name if self.leader else None,
            "meeting_day": self.meeting_day,
            "member_count": len(self.members),
        }


class Service(db.Model):
    __tablename__ = "services"

    id = db.Column(db.Integer, primary_key=True)
    church_id = db.Column(db.Integer, db.ForeignKey("churches.id"), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    type = db.Column(db.String(20), default="sunday")  # sunday | midweek | special
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    attendance_records = db.relationship("AttendanceRecord", backref="service", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "date": self.date.isoformat(),
            "type": self.type,
        }


class AttendanceRecord(db.Model):
    """
    One row per member per service. Created fresh every time
    submit_attendance() runs — this is the live weekly snapshot,
    not a persistent list. A name reappearing after attending is
    just a new record with present=False, nothing more.
    """
    __tablename__ = "attendance_records"

    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey("services.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    present = db.Column(db.Boolean, nullable=False)

    follow_up_status = db.Column(db.String(30), default="not_applicable")
    # not_applicable | not_started | reached_ok | reached_concern |
    # no_answer | invalid_number
    follow_up_by = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=True)
    follow_up_note = db.Column(db.Text)
    follow_up_completed_at = db.Column(db.DateTime, nullable=True)
    escalated = db.Column(db.Boolean, default=False)

    assignments = db.relationship("FollowUpAssignment", backref="attendance_record", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "member_id": self.member_id,
            "member_name": self.member.full_name if self.member else None,
            "member_phone": self.member.phone if self.member else None,
            "member_area": self.member.area if self.member else None,
            "cell_name": self.member.cell.name if self.member and self.member.cell_id and self.member.cell else "Unassigned",
            "date": self.date.isoformat(),
            "present": self.present,
            "follow_up_status": self.follow_up_status,
            "follow_up_note": self.follow_up_note,
            "escalated": self.escalated,
            "consecutive_absences": self.member.consecutive_absences if self.member else None,
        }


class Visitor(db.Model):
    __tablename__ = "visitors"

    id = db.Column(db.Integer, primary_key=True)
    church_id = db.Column(db.Integer, db.ForeignKey("churches.id"), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(30))
    date_visited = db.Column(db.Date, default=date.today)
    invited_by = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=True)
    converted_to_member_id = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "phone": self.phone,
            "date_visited": self.date_visited.isoformat() if self.date_visited else None,
            "converted": self.converted_to_member_id is not None,
        }


class EventRSVP(db.Model):
    """
    RSVP intent, separate from actual AttendanceRecord. A member who
    RSVPs yes and then doesn't show is a stronger drift signal than
    a plain unannounced absence -- the follow-up UI can surface
    "said yes, didn't come" differently from "just missed it."
    """
    __tablename__ = "event_rsvps"

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("services.id"), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=False)
    response = db.Column(db.String(20), default="yes")  # yes | no | maybe
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    service = db.relationship("Service", backref="rsvps")
    member = db.relationship("Member", foreign_keys=[member_id])

    def to_dict(self):
        return {
            "id": self.id,
            "service_id": self.service_id,
            "member_id": self.member_id,
            "member_name": self.member.full_name if self.member else None,
            "response": self.response,
        }


class FollowUpAssignment(db.Model):
    """
    One row per absence that needs a call. Assignments STACK —
    if a leader never completes last week's call and the member
    misses again, the old assignment stays open (status=pending)
    alongside the new one. This is intentional: it's how the app
    surfaces leaders who are dropping the ball, not just how it
    logs absences.
    """
    __tablename__ = "follow_up_assignments"

    id = db.Column(db.Integer, primary_key=True)
    attendance_record_id = db.Column(db.Integer, db.ForeignKey("attendance_records.id"), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("members.id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending | completed
    reason = db.Column(db.String(30), default="weekly_absence")  # weekly_absence | escalation
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    assignee = db.relationship("Member", foreign_keys=[assigned_to])

    def to_dict(self):
        record = self.attendance_record
        return {
            "id": self.id,
            "status": self.status,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "attendance_record": record.to_dict() if record else None,
        }