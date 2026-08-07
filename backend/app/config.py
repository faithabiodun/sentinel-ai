from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = ""
    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    bedrock_model_id: str = "us.anthropic.claude-sonnet-4-6-20250929-v1:0"
    bedrock_embed_model_id: str = "amazon.titan-embed-text-v2:0"
    s3_bucket: str = ""
    jwt_secret: str = "change-me-before-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_hours: int = 24
    cors_origin: str = "http://localhost:3000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
