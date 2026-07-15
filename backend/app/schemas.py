from pydantic import BaseModel


class GenerateRequest(BaseModel):
    prompt: str


class GenerateResponse(BaseModel):
    id: int
    prompt: str
    rules: dict
    analysis: dict
    created_at: str
