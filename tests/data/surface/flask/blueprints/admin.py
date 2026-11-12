from flask import Blueprint, abort, request, send_file, session

admin_bp = Blueprint("admin", __name__)


@admin_bp.before_request
def require_admin():
    if not session.get("user_is_admin"):
        abort(403)


@admin_bp.route("/logs/<path:name>")
def logs(name):
    return send_file("/var/log/app/" + name)


@admin_bp.route("/import", methods=["POST"])
def import_data():
    upload = request.files["dump"]
    return {"size": len(upload.read())}
