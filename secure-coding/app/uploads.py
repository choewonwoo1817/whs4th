"""이미지 업로드 검증·저장 (SR-13, SR-14).

방어 순서:
1) 확장자 화이트리스트   → SVG·HTML 등 스크립트 실행 가능 포맷 원천 차단
2) 크기 제한
3) Pillow 로 실제 이미지인지 검증(위장 파일 차단) + 재인코딩(내장 스크립트/메타 제거)
4) 서버가 새 무작위 파일명 부여(경로 조작·덮어쓰기 방지)
"""
import io
import os
import uuid

from flask import current_app
from PIL import Image, UnidentifiedImageError
from PIL.Image import DecompressionBombError

ALLOWED_EXT = {"jpg", "jpeg", "png", "gif", "webp"}
# Pillow 포맷명 → 저장 확장자 (SVG 는 래스터 포맷이 아니므로 애초에 목록에 없음)
FORMAT_EXT = {"JPEG": "jpg", "PNG": "png", "GIF": "gif", "WEBP": "webp"}

# 압축폭탄(decompression bomb) 방어: 픽셀 수 상한 (약 25MP)
MAX_PIXELS = 25_000_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS * 2   # 이 값 초과 시 Pillow가 DecompressionBombError


class UploadError(Exception):
    pass


def save_image(file_storage):
    """검증 통과 시 저장된 파일명을 반환. 실패 시 UploadError."""
    filename = file_storage.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        raise UploadError("허용되지 않는 이미지 형식입니다. (jpg/png/gif/webp)")

    data = file_storage.read()
    if not data:
        raise UploadError("빈 파일입니다.")
    if len(data) > current_app.config["MAX_UPLOAD_BYTES"]:
        raise UploadError("이미지 용량이 너무 큽니다.")

    # 내용이 실제 이미지인지 검증 (확장자만 .png 로 위장한 파일 차단)
    try:
        probe = Image.open(io.BytesIO(data))
        probe.verify()
    except (UnidentifiedImageError, OSError, ValueError, DecompressionBombError):
        raise UploadError("유효한 이미지 파일이 아닙니다.")

    # verify() 후에는 객체를 재사용할 수 없어 다시 연다
    img = Image.open(io.BytesIO(data))
    fmt = img.format
    if fmt not in FORMAT_EXT:
        raise UploadError("허용되지 않는 이미지 형식입니다.")

    # 해상도 상한 검사 (전체 디코딩 전에 헤더의 크기로 차단, DoS 방지)
    if img.size[0] * img.size[1] > MAX_PIXELS:
        raise UploadError("이미지 해상도가 너무 큽니다.")

    out_ext = FORMAT_EXT[fmt]
    if fmt == "JPEG" and img.mode in ("RGBA", "P"):
        img = img.convert("RGB")

    new_name = f"{uuid.uuid4().hex}.{out_ext}"
    upload_dir = current_app.config["UPLOAD_DIR"]
    os.makedirs(upload_dir, exist_ok=True)
    # 재인코딩 저장 → 원본 바이트(내장 스크립트/EXIF 등)를 그대로 두지 않는다
    try:
        img.save(os.path.join(upload_dir, new_name), format=fmt)
    except DecompressionBombError:
        raise UploadError("이미지 해상도가 너무 큽니다.")
    return new_name


def delete_image(name):
    """저장된 업로드 파일을 삭제(상품 삭제/이미지 교체 시 고아 파일 방지)."""
    if not name:
        return
    safe = os.path.basename(name)   # 경로 이탈 방지
    path = os.path.join(current_app.config["UPLOAD_DIR"], safe)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
