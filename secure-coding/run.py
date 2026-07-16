"""진입점: python run.py 또는 flask --app run <command>."""
import os

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    # 포트는 PORT 환경변수로 변경 가능 (macOS는 5000을 AirPlay가 점유하는 경우가 많음)
    port = int(os.environ.get("PORT", "5000"))
    # 개발 서버. 운영에서는 DEBUG=False, HTTPS(ngrok) 뒤에서 실행.
    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=app.config["DEBUG"],
        allow_unsafe_werkzeug=True,
    )
