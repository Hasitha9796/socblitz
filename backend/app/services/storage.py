"""MinIO object storage service for SocBlitz."""
from minio import Minio
from minio.error import S3Error
from loguru import logger
from app.core.config import settings


def get_minio_client() -> Minio:
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ROOT_USER,
        secret_key=settings.MINIO_ROOT_PASSWORD,
        secure=settings.MINIO_SECURE,
    )


def init_minio_buckets() -> None:
    """Create required buckets on startup."""
    client = get_minio_client()
    buckets = [
        settings.MINIO_BUCKET_CASES,
        settings.MINIO_BUCKET_REPORTS,
        settings.MINIO_BUCKET_ARTIFACTS,
    ]
    for bucket in buckets:
        try:
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)
                logger.info(f"MinIO bucket created: {bucket}")
        except S3Error as e:
            logger.error(f"MinIO bucket error for {bucket}: {e}")


def upload_file(bucket: str, object_name: str, file_path: str, content_type: str = "application/octet-stream") -> str:
    client = get_minio_client()
    client.fput_object(bucket, object_name, file_path, content_type=content_type)
    return f"{settings.MINIO_ENDPOINT}/{bucket}/{object_name}"


def get_presigned_url(bucket: str, object_name: str, expires_seconds: int = 3600) -> str:
    from datetime import timedelta
    client = get_minio_client()
    return client.presigned_get_object(bucket, object_name, expires=timedelta(seconds=expires_seconds))
