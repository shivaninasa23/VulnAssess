from flask import render_template,jsonify,request
def register_errors(app):
    @app.errorhandler(400)
    def bad_request(e): return (jsonify(error="Invalid request") if request.is_json else render_template("error.html",message="Invalid request or expired form token."),400)
    @app.errorhandler(404)
    def not_found(e): return render_template("error.html",message="The requested page was not found."),404
    @app.errorhandler(429)
    def limited(e): return render_template("error.html",message="Too many attempts. Please wait before trying again."),429
    @app.errorhandler(500)
    def server_error(e): app.logger.exception("Unhandled application error"); return render_template("error.html",message="Something went wrong. Please try again."),500
